# Network Scanner - Skeniranje Mreže

Skripta za skeniranje mreže i pronalaženje svih uređaja sa human-readable opisima i lepim prikazom.

## Instalacija

```bash
# Instaliraj potrebne biblioteke (opciono, za lepši prikaz)
pip install -r requirements_network_scanner.txt

# Ili samo:
pip install rich
```

## Korišćenje

### Osnovno korišćenje (automatska detekcija mreže)

```bash
python3 network_scanner.py
```

### Skeniranje specifične mreže

```bash
python3 network_scanner.py --network 192.168.1.0/24
```

### Brže skeniranje (bez skeniranja portova)

```bash
python3 network_scanner.py --no-ports
```

### JSON izlaz (za skripte)

```bash
python3 network_scanner.py --json
```

## Opcije

- `--network`, `-n`: Specifikuj mrežu za skeniranje (npr. `192.168.1.0/24`)
- `--no-ports`: Ne skeniraj portove (brže, ali manje informacija)
- `--json`: Izlaz u JSON formatu (za automatsku obradu)

## Šta skripta prikazuje

Za svaki pronađeni uređaj, skripta prikazuje:

- **IP Adresa**: IP adresa uređaja
- **Hostname**: Ime računara/uređaja (ako je dostupno)
- **MAC Adresa**: Fizička adresa mrežne kartice
- **Proizvođač**: Proizvođač uređaja (na osnovu MAC adrese)
- **Tip Uređaja**: Automatski identifikovan tip (Smart TV, Router, Printer, itd.)
- **Servisi**: Otvoreni portovi i servisi (SSH, HTTP, VIDAA TV, itd.)
- **Ping (ms)**: Vreme odziva

## Primeri

```bash
# Skeniraj lokalnu mrežu
python3 network_scanner.py

# Skeniraj specifičnu mrežu bez portova (brže)
python3 network_scanner.py --network 192.168.0.0/24 --no-ports

# JSON izlaz za obradu
python3 network_scanner.py --json > devices.json
```

## Napomene

- Skripta zahteva root/sudo pristup za neke operacije (npr. ARP tabela)
- Skeniranje portova može biti sporo na velikim mrežama
- Neki uređaji možda neće biti pronađeni ako blokiraju ping (ICMP)
- MAC adrese se mogu dobiti samo za uređaje u istoj mrežnoj sekciji

## Podržani tipovi uređaja

Skripta automatski identifikuje:
- Smart TV-ove (Samsung, LG, Sony, Hisense, itd.)
- Apple uređaje (iPhone, iPad, Mac)
- Routere/Gateway-ove
- Printere
- NAS/Storage uređaje
- Media servere (Plex, iTunes)
- Chromecast uređaje
- Raspberry Pi
- Virtualne mašine
- I druge...

## Zahtevi

- Python 3.6+
- `rich` (opciono, za lepši prikaz - skripta radi i bez njega)
- Linux/macOS/Windows (testirano na Linux-u)

