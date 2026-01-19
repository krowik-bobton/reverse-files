; Program do bajtowego odwracania zawartości pliku w assemblerze x86-64
; Program jest w stanie odwracać duże pliki (ponad 4GiB) z jednoczesnym użyciem
; niewielkiej ilości dodatkowej pamięci.

; Strategia programu:
; Dopóki nieodwrócona część pliku ma rozmiar >= 2MB:
; Dokonaj zamiany (odwrócenia) pierwszego 1MB z ostatnim 1MB nieodwróconej części
; Użyj sys_mmap do mapowania krańców pliku.
; Kontynuuj aż nieodwrócona część będzie miała rozmiar < 2MB
; Dla małej części (< 2MB): zmapuj całość i odwróć prostą pętlą.
;
; W przypadku napotkania jakiegokolwiek błędu funkcji systemowej
; program natychmiast przerywa swoje działanie i ustawia sygnał wyjściowy na 1

section .data
  ; Stałe dla wywołań funkcji systemowych :
  SYS_OPEN equ 2                ; otwieranie pliku
  SYS_EXIT equ 60               ; zakończenie programu
  SYS_FSTAT equ 5               ; pobieranie statystyk pliku
  SYS_MMAP   equ 9              ; mapowanie części pliku do pamięci
  SYS_MUNMAP equ 11             ; usuwanie mapowania pamięci
  SYS_MSYNC  equ 26             ; synchronizacja zmian w zmapowanej pamięci
  SYS_CLOSE  equ 3              ; zamykanie podanego pliku

  ; Parametry dla funkcji sys_mmap :
  PROT_READ  equ 1              ; pozwolenie na czytanie
  PROT_WRITE equ 2              ; pozwolenie na pisanie
  MAP_SHARED equ 1              ; współdzielone mapowanie (zmiany widoczne w pliku)

  ; Parametr dla sys_open :
  O_RDWR equ 2                  ; informacja o możliwości czytania/pisania do pliku

  ; Maski bitowe dla analizy typu pliku (wyciąganie informacji z sys_fstat)
  S_IFMT    equ 0o170000        ; maska do izolowania typu pliku
  S_IFREG   equ 0o100000        ; ciąg świadczący, że plik jest typu zwykłego
                                ; czyli można go odwracać

  ; Stałe rozmiarów pamięci :
  PAGE_SIZE equ 4096            ; standardowy rozmiar strony pamięci (4KB)
  CHUNK_SIZE equ 0x100000       ; rozmiar bloku (krańca) do mapowania : 1MB


section .bss
    buforfstat resb 144         ; bufor na strukturę stat z sys_fstat

global _start

section .text
    ; Local variables (kept on stack):
    %define ptr_block_left          rbp - 8   ; użytkowy wskaźnik na początek lewego bloku
                                              ; (odpowiadający miejscu od którego odwracamy krańce)
    %define ptr_block_right         rbp - 16  ; użytkowy wskaźnik na blok prawy (jak wyżej)
    %define ptr_block_right_orig    rbp - 24  ; oryginalny wskaźnik na blok prawy
                                              ; (zwrócony przez sys_mmap)
    %define ptr_block_left_orig     rbp - 32  ; oryginalny wskaźnik na blok lewy
                                              ; (zwrócony przez sys_mmap)
    %define size_block_left         rbp - 40  ; rozmiar lewego mapowania
    %define size_block_right        rbp - 48  ; rozmiar prawego mapowania
    %define stat_buffer             rbp - 192 ; bufor na strukturę stat z funkcji fstat (144 bajty)

_start:
    push rbp
    mov rbp, rsp
    sub rsp, 192          ; rezerwujemy miejsce na zmienne lokalne, 144 na stat_buffer
                          ; oraz 48 na wskaźniki i rozmiary bloków

.otwieranie_pliku:
    ; Parametry przekazywane do programu są na stosie o początku w rsp.
    mov rcx, [rbp + 8]    ; Ładuje do rcx liczbę przekazanych parametrów
    cmp rcx, 2            ; Sprawdzamy czy są tylko dwa parametry
                          ; Przy czym pierwszy to będzie nazwa tego programu
                          ; A drugi to nazwa pliku, który należy odwrócić.
    jne .wyjdz_blad     ; Jeśli nie ma dwóch parametrów, to błąd.

    ; w [rsp + 16] przechowywana jest nazwa pliku do odwrócenia. Otwieramy go:
    mov rax, SYS_OPEN     ; rax = informacja o użyciu sys_open
    mov rdi, [rbp + 24]   ; rdi = nazwa podanego pliku.
    mov rsi, O_RDWR       ; rsi = informacja o uprawnieniach (czytanie i pisanie)
    mov rdx, 0            ; rdx = mode (0, czyli nieistotny)
    syscall               ; wywołujemy sys_open o powyższych parametrach.

    ; jeśli sys_open zakończyło się niepowodzeniem to rax ma wartość ujemną
    cmp rax, 0
    jl .wyjdz_blad  ; jeśli rax < 0 to kończymy działanie (nie zamykamy pliku, bo się nie otworzył)

    ; jeśli sys_open się powiodło, to w rax jest file descriptor, za jego
    ; pomocą odwołujemy się do otwartego pliku.
    mov r12, rax          ; w r12 przechowujemy file descriptor

; Po otwarciu pliku, sprawdzamy czy jest to plik "zywczajny" (możliwy do odwrócenia)
; oraz jeśli tak to czy ma liczbę bajtów większą lub równą 2. Jeśli tak to
; przechodzimy do odwracania pliku.
.badanie_podanego_pliku:
    ; zbieramy statystyki dotyczące pliku z użyciem sys_fstat:
    mov rax, SYS_FSTAT
    mov rdi, r12                  ; rdi = file descriptor (trzymany w r12)
    lea rsi, [stat_buffer]     ; rsi = wskaźnik do buforu dla structa wynikowego
    syscall

    ; patrzymy czy udane:
    cmp rax, 0
    jl .posprzataj_i_wyjdz          ; jeśli nieudane to zamykamy plik i kończymy


    ; Sprawdzamy czy ten plik jest zwyczajnego typu
    mov eax, [stat_buffer + 24] ; tu jest trzymany typ pliku
    and eax, S_IFMT                ; wyodrębniamy typ pliku
    cmp eax, S_IFREG               ; sprawdzamy czy zwyczajny
    jne .posprzataj_i_wyjdz          ; jeśli nie to zamykami plik i kończymy

    ; Skoro tu jesteśmy to plik jest zwyczajny. Jeśli ma < 2 bajty nie odwracamy
    ; rozmiar pliku jest przecowywany na miejscu 48 w zwróconej strukturze
    mov r13, [stat_buffer + 48] ; zapisujemy rozmiar pliku do r13
    cmp r13, 2
    jb .sukces_wyjscie             ; jeśli ma mniej niż 2 bajty, sukces.

.inicjalizacja_przed_petla:
    ; inicjalizacja wskaźników na początek i koniec pliku
    mov r14, 0            ; start = r14 = 0 (pierwszy bajt)
    mov r15, r13          ;
    dec r15               ; r15 = end = rozmiar pliku - 1 (początek ostatniego bajtu)

    ; Liczymy liczbę bajtów pomiędzy start i end (włącznie)
    mov rax, r15          ; rax = end
    sub rax, r14          ; rax = end - start
    inc rax               ; rax = end - start + 1
                          ; tyle jest bajtów pomiędzy start i end (włącznie)

    ; sprawdzamy czy możemy pomapować LEWO (1MB) i PRAWO(1MB), tak żeby
    ; części się na siebie nie nakładały :
    mov rdi, CHUNK_SIZE
    shl rdi, 1              ; rdi = CHUNK_SIZE * 2
    cmp rax, rdi
    jb .odwroc_maly_plik    ; jeśli mniejsze, to musimy skoczyć do odwracania
                            ; małego pliku (części pliku, mającej mniej niż 2MB)

; Skoro tu jesteśmy to musimy odwracać po 1MB z przodu i tyłu aż nie uzyskamy
; części środkowej mniejszej niż 2MB.
.petla_glowna:
    ; do sys_mmap, podany offset pliku musi być wielokrotnością PAGE_SIZE
    ; musimy obliczyć odpowiednie wartości, które podamy do sys_mmap oraz
    ; zapamiętać przesunięcia indeksów względem tych, od których chcemy zacząć
    ; odwracanie. Ilustruje to następujący przykład (na mniejszą skalę):
    ; chcemy zmapować bajty pliku od tego na miejscu nr 5 do tego na miejscu
    ; numer 5000 (numerujemy od 0). Zatem offset pliku, który podamy do sys_mmap
    ; bedzie wynosił 0, ponieważ jest to zaokrąglenie 5 w dół do wielokrotności
    ; page_size. Zatem mapowanie odbędzie się od 0 do 5000 bajtu pliku, ale
    ; my chcemy korzystać tylko z mapowania od 5 do 5000, dlatego
    ; musimy zapamiętać:

    ; [ptr_block_left] -> użytkowy adres, początek zmapowanego bloku + przesunięcie
    ;                   (dla przykładu przesunięcie wynosi 5).
    ; [ptr_block_left_ORYGINALNY] -> adres początku zmapowanego bloku
    ;                   (wartość rax po poprawnym wykonaniu sys_mmap)
    ; [size_blok_left] -> długość mapowanego bloku (od 0 do 5000).
    ; analogicznie dla bloków prawych.

    ; wyrównanie offsetu bloku lewego do wielokrotności PAGE_SIZE (w dół) :
    mov rax, r14            ; rax = start
    xor rdx, rdx            ; rdx = 0, czyszczenie
    mov rcx, PAGE_SIZE      ; rcx = dzielnik = PAGE_SIZE
    div rcx                 ; rax = start / PAGE_SIZE (podłoga z dzielenia)
    mul rcx                 ; rax = (start / PAGE_SIZE) * PAGE_SIZE
    ; teraz w rax jest offset pliku, który podajemy do sys_mmap
    mov r9, rax             ; r9 = offset pliku
    mov rbx, r14
    sub rbx, r9             ; rbx = start - offset pliku = przesunięcie

    ; mapowanie bloku LEWEGO
    mov rax, SYS_MMAP
    mov rdi, 0              ; addr = NULL (domyślny)
    mov rsi, CHUNK_SIZE
    add rsi, rbx            ; dlugosc mapowania = CHUNK_SIZE + przesuniecie
    mov rdx,  PROT_READ | PROT_WRITE  ; zarówno czytamy, jak i piszemy
    mov r10, MAP_SHARED     ; współdzielone mapowanie (zmiany widoczne w pliku)
    mov r8, r12             ; r8 = r12 = file descriptor
    ; r9 już trzyma offset pliku
    syscall

    ; w przypadku powodzenia, mmap zwraca (do rax) pointer na zmapowany obszar
    ; ujemny rax jest błędem.
    cmp rax, 0
    jl .posprzataj_i_wyjdz    ; jeśli rax < 0 to błąd

    ; jeśli powodzenie, to zapamiętujemy potrzebne dane
    mov [ptr_block_left_orig], rax
    ; użytkowy adres otrzymamy poprzez dodanie przesunięcia do adresu z mapowania
    add rax, rbx                ; dodajemy przesunięcie
    mov [ptr_block_left], rax
    ; rsi przechowuje CHUNK_SIZE + rbx (tak podaliśmy wywołując sys_mmap)
    mov [size_block_left], rsi


    ; mapowanie bloku PRAWEGO
    ; musimy obliczyć początek bloku prawego w odwracanym pliku
    ; będzie to wynosiło: end - CHUNK_SIZE + 1
    mov r11, r15             ; r11 = end
    sub r11, CHUNK_SIZE      ; r11 = end - CHUNK_SIZE
    inc r11                  ; r11 = end - CHUNK_SIZE + 1
    ;musimy go wyrównać w dół do PAGE_SIZE
    mov rax, r11
    xor rdx, rdx
    mov rcx, PAGE_SIZE
    div rcx                 ; rax = r11 / page_size (podłoga z dzielenia)
    mul rcx                 ; rax = (r11 / PAGE_SIZE) * PAGE_SIZE
    mov r9, rax             ; w r9 mamy teraz wyrównany offset

    ; Liczymy ile bajtów "za wcześnie" mamy offset (obliczamy przesunięcie)
    mov rbx, r11            ; r11 = oryginalny offset w pliku
    sub rbx, r9             ; r9 = zaokrąglony w dół offset.
    ; teraz rbx trzyma przesunięcie

    ; mapujemy blok prawy :
    mov rax, SYS_MMAP
    mov rdi, 0
    mov rsi, rbx
    add rsi, CHUNK_SIZE     ; rsi = CHUNK_SIZE + przesunięcie (długość mapowania)
    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_SHARED
    mov r8, r12             ; r8 = r12 = file descriptor
    ; r9 już ma offset
    syscall

    ; Jeśli się powiodło, to w rax trzymany jest adres na zmapowaną pamięć,
    ; jeśli się nie powiodło to rax jest ujemny.
    ; sprawdzamy czy się powiodło:
    cmp rax, 0
    jl .posprzataj_i_wyjdz    ; rax < 0, zakończ program

    mov [ptr_block_right_orig], rax   ; zapisujemy oryginalny wskaźnik
    mov rsi, rbx
    add rsi, CHUNK_SIZE     ; rsi = przesunięcie + CHUNK_SIZE
    mov [size_block_right], rsi          ; zapisujemy długość mapowania

    add rax, rbx            ; przesuń adres mapowania o przesunięcie
    mov [ptr_block_right], rax  ; zapisz użytkowy adres


    ; W tej chwili mamy zmapowane bloki lewy i prawy, każdy o długości użytkowej
    ; 1MB (przez zaokrąglenia, ich długość może być większa). Musimy
    ; w pętli zamienić ze sobą odpowiednie bajty bloku lewego i prawego.
    ; pętla zamiany bloków, wywołuje się CHUNK_SIZE razy, bo tyle wynosi
    ; użytkowa długość każdego z bloków.
    xor rcx, rcx           ; i = 0

.petla_zamiana_blokow:
    cmp rcx, CHUNK_SIZE
    jge .po_zamianie       ; if i>=CHUNK_SIZE, koniec pętli

    ; Liczymy miejsca, które będą zamieniane
    ; p = ptr_block_left + i
    ; q = ptr_block_right + CHUNK_SIZE - i - 1
    mov rsi, [ptr_block_left]
    add rsi, rcx           ; rsi = p = ptrLEWY + i

    mov rax, CHUNK_SIZE
    sub rax, rcx
    dec rax               ; rax = CHUNK_SIZE - i - 1
    mov rdi, [ptr_block_right]
    add rdi, rax          ; rdi = q = ptrPRAWY + CHUNK_SIZE - i - 1

    ; pozostało nam zamienić bajty
    mov al, [rsi]         ; al to ostatni bajt z eax
    mov ah, [rdi]         ; ah to przedostatni bajt z eax
    mov [rsi], ah
    mov [rdi], al

    inc rcx
    jmp .petla_zamiana_blokow

.po_zamianie:
    ; po zamianie bloków, musimy zrobić sys_msync dla każdego mapowania, żeby
    ; być pewnym że zmiany się zaaplikowały
    ; Musimy też usunąć mapowanie za pomocą sys_munmap

    ; sys_msync dla bloku lewego
    mov rax, SYS_MSYNC
    mov rdi, [ptr_block_left_orig]      ; adres początkowy mapowania
    mov rsi, [size_block_left]             ; długość mapowania
    mov rdx, 0                                  ; brak specjalnych flag
    syscall
    ; jeśli niepowodzenie
    cmp rax, 0
    jl .posprzataj_i_wyjdz                        ; rax < 0, kończymy z błędem.


    ; sys_msync dla bloku PRAWEGO
    mov rax, SYS_MSYNC
    mov rdi, [ptr_block_right_orig]     ; adres początkowy mapowania
    mov rsi, [size_block_right]            ; długość mapowania
    mov rdx, 0                                  ; brak specjalnych flag
    syscall

    ; jeśli niepowodzenie zakończ z błędem
    cmp rax, 0
    jl .posprzataj_i_wyjdz

    ; zwalniamy mapowania dla bloku LEWEGO z użyciem sys_munmap
    mov rax, SYS_MUNMAP
    mov rdi, [ptr_block_left_orig]      ; adres początkowy mapowania
    mov rsi, [size_block_left]             ; długość mapowania
    syscall

    ; gdy niepowodzenie, zakończ z błędem
    cmp rax, 0
    jl .posprzataj_i_wyjdz

    ; zwalniamy mapowania dla bloku PRAWEGO z uzyiem sys_munmap
    mov rax, SYS_MUNMAP
    mov rdi, [ptr_block_right_orig]
    mov rsi, [size_block_right]
    syscall

    ; w przypadku niepowodzenia, zakończ z błędem
    cmp rax, 0
    jl .posprzataj_i_wyjdz

.operacje_koncowe_glownej_petli:
    ; musimy zaktualizować start i end
    add r14, CHUNK_SIZE                     ; start += CHUNK_SIZE
    sub r15, CHUNK_SIZE                     ; end -= CHUNK_SIZE

    ; liczymy ile jest nieodwróconych bajtów pomiędzy start i end (włącznie)
    mov rax, r15
    sub rax, r14
    inc rax                                 ; rax = end - start + 1

    ; sprawdzamy czy bajtów środka jest >= 2 * CHUNK_SIZE
    mov rsi, CHUNK_SIZE
    shl rsi, 1
    cmp rax, rsi
    jge .petla_glowna                       ; jeśli tak, to kolejny obieg pętli

; Jeśli tu jesteśmy, to potencjalnie została niewielka (< 2MB)  nieodwrócona
; część pliku pośrodku.

.odwroc_maly_plik:
    ; liczymy ile jest bajtów nieodwróconej części
    mov rax, r15
    sub rax, r14
    inc rax           ; rax = r15 - r14 + 1
    ; rax ma teraz rozmiar części, którą pozostało odwrócić

    ; gdy liczba bajtów środka jest mniejsza lub równa 1, nic nie robimy.
    cmp rax, 1
    jle .sukces_wyjscie ;

    mov rbx, rax      ; rbx, ma teraz rozmiar części, którą pozostało odwrócić

    ; Musimy zmapować pozostałą całość, ale najpierw tak jak wcześniej,
    ; zaokrąglamy offset pliku do wielokrotności page_size
    mov rax, r14                           ; rax = start
    xor rdx, rdx                           ; rdx = 0
    mov rcx, PAGE_SIZE                     ; rcx = PAGE_SIZE
    div rcx                                ; rax = start / PAGE_SIZE (podłoga)
    mul rcx                                ; rax *= PAGE_SIZE
    mov r9, rax                            ; r9 trzyma wyrównany offset

    mov rsi, r14
    sub rsi, r9       ; rsi = start - wyrównany offset = przesunięcie

    ; długość mapowania = przesunięcie + długość środka
    mov rax, rsi      ; rax = przesunięcie
    add rax, rbx      ; rax = przesunięcie + rozmiar środka

    mov [size_block_left], rax       ; zapisujemy rozmiar bloku

    ; mapujemy blok (traktujemy go jak lewy)
    mov rax, SYS_MMAP
    mov rdi, 0
    mov rsi, [size_block_left]       ; długość całkowita
    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_SHARED
    mov r8, r12                           ; w r12 jest file descriptor
    ; r9 już przechowuje wyrównany offset
    syscall

    ; w przypadku niepowodzenia wychodzimy z kodem 1
    cmp rax, 0
    jl .posprzataj_i_wyjdz

    ; jeśli mapowanie się powiodło to rax = adres mapowania
    ; tak jak w pętli głównej zapisujemy adres mapowania
    mov [ptr_block_left_orig], rax
    add rax, r14                          ; rax += start
    sub rax, r9                           ; rax -= wyrównany offset
    mov [ptr_block_left], rax           ; użytkowy adres

    ; odwracamy w pętli bajty bloku.
    mov rdx, rbx                          ; rdx = rbx = rozmiar obracanego obszaru
    shr rdx, 1                            ; rdx = rozmiar obszaru / 2
    xor rcx, rcx                          ; i = 0, tym iterujemy

.petla_odwroc_srodek:
    cmp rcx, rdx                          ; if( i >= dlugosc / 2) koniec pętli
    jge .po_odwroceniu_srodka

    ; zamieniamy bity p i q :
    ; p = [ptr_block_left] + i
    ; q = [ptr_block_left] + długość obszaru - i - 1

    ; obliczamy p
    mov rsi, [ptr_block_left]           ; p = [ptr_block_left]
    add rsi, rcx                          ; rsi = p = [ptr_block_left] + i

    ; obliczamy q
    mov rax, rbx                          ; rax = długość obszaru
    sub rax, rcx                          ; rax = długość obszaru - i
    dec rax                               ; rax = długość obszaru - i - 1
    mov rdi, [ptr_block_left]           ; rdi = [ptr_block_left]
    add rdi, rax                          ; rdi = q = [ptr_block_left] - rax

    ; zamiana bajtów
    mov al, [rsi]
    mov ah, [rdi]
    mov [rsi], ah
    mov [rdi], al

    ; i++
    inc rcx
    jmp .petla_odwroc_srodek

.po_odwroceniu_srodka:
    ; musimy zsynchronizować zmiany używając sys_msync
    mov rax, SYS_MSYNC
    mov rdi, [ptr_block_left_orig] ; adres mapowania
    mov rsi, [size_block_left]        ; długość mapowania
    mov rdx, 0                             ; brak specjalnych flag
    syscall

    cmp rax, 0
    jl .posprzataj_i_wyjdz                   ; jeśli się nie powiodło, wyjdź z 1

    ; usuwamy mapowanie środka
    mov rax, SYS_MUNMAP
    mov rdi, [ptr_block_left_orig] ; adres mapowania
    mov rsi, [size_block_left]        ; długość mapowania
    syscall

    cmp rax, 0
    jl .posprzataj_i_wyjdz                   ; jeśli błąd to wyjdź

; mamy różne scenariusze zakończeń programu:
; 1) plik się otworzył, wszystko pomyślnie, trzeba plik zamknąć i
; zakończyć program z sygnałem 0
.sukces_wyjscie:

    ; zamykamy plik
    mov rax, SYS_CLOSE
    mov rdi, r12                           ; deskryptor pliku
    syscall
    cmp rax, 0                             ; jeśli się nie powiodło to błąd.
    jl .wyjdz_blad

    mov rax, SYS_EXIT
    xor rdi, rdi                           ; rdi = 0 (kod na wyjście)

    mov rsp, rbp
    pop rbp

    syscall

; 2) plik się otworzył, ale coś w międzyczasie poszło nie tak
.posprzataj_i_wyjdz:
    ; zamknij plik
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall
; przechodzimy niżej do zakończenia programu z sygnałem 1

; 3) jeśli błąd stwierdzono przed / w trakcie otwierania pliku lub podczas zamykania
.wyjdz_blad:
    ; wychodzimy z sygnałem 1 (błąd)
    mov rax, SYS_EXIT
    mov rdi, 1

    mov rsp, rbp
    pop rbp

    syscall
