from sniffer import Sniffer
from colorama import init, Fore
import argparse

init(autoreset=True)

def main(interface, pcapfile, export, protocol, text, display):
    sniffer = Sniffer()

    # Importar captura desde archivo o iniciar captura en vivo
    if pcapfile:
        print(Fore.GREEN + f"[+] Importando archivo: {pcapfile}")
        sniffer.import_capture(pcapfile)
    else:
        print(Fore.GREEN + f"[+] Comenzando captura en vivo en la interfaz: {interface}")
        sniffer.capture_live(interface=interface)

    # Aplicar filtros si se proporcionan
    filtered_packets = sniffer.capture_packet

    if protocol:
        print(Fore.YELLOW + f"[+] Filtrando por protocolo: {protocol}")
        filtered_packets = sniffer.filter_by_protocol(protocol)

    if text:
        print(Fore.YELLOW + f"[+] Filtrando por texto: {text}")
        filtered_packets = sniffer.filter_by_text(text)

    # Mostrar paquetes filtrados o capturados
    if display:
        print(Fore.CYAN + "[+] Mostrando paquetes:")
        sniffer.print_packets(filtered_packets)

    # Exportar los paquetes filtrados o capturados
    if export:
        print(Fore.GREEN + f"[+] Exportando paquetes a: {export}")
        sniffer.export_to_pcap(filtered_packets, export)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=f'{Fore.LIGHTBLUE_EX}Desarrollado por: N111X\n{Fore.LIGHTBLUE_EX}Sniffer.',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True
    )

    parser.add_argument("-i", "--interface", help="Interfaz de red para la captura en vivo", type=str, default="Ethernet")
    parser.add_argument("-r", "--read-pcap", help="Importar un archivo .pcap para su analisis", type=str)
    parser.add_argument("-e", "--export-pcap", help="Exportar el analisis en un fichero .pcap", type=str)
    parser.add_argument("-p", "--protocol", help="Filtrar paquetes por un protocolo especifico", type=str)
    parser.add_argument("-t", "--text", help="Filtrar paquetes que contengan un texto especifico", type=str)
    parser.add_argument("-d", "--display", help="Mostrar los paquetes en la terminal", action="store_true")

    args = parser.parse_args()

    main(
        interface=args.interface,
        pcapfile=args.read_pcap,
        export=args.export_pcap,
        protocol=args.protocol,
        text=args.text,
        display=args.display
    )
