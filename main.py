from sniffer import Sniffer
from colorama import init, Fore
import argparse

init(autoreset=True)


def main(interface, pcapfile, export, protocol, text, display):
    # Crea una instancia de la clase Sniffer
    sniffer = Sniffer()

    # Si se proporciona un archivo .pcap, lo importamos
    if pcapfile:
        print(Fore.GREEN + f"[+] Importando archivo: {pcapfile}")
        sniffer.import_capture(pcapfile)

    # Si no se proporciona un archivo .pcap, comenzamos a capturar en vivo
    else:
        print(Fore.GREEN + f"[+] Comenzando captura en vivo en la interfaz: {interface}")
        sniffer.capture_live(interface=interface)

    # Filtrar los paquetes si se ha proporcionado un protocolo
    if protocol:
        print(Fore.YELLOW + f"[+] Filtrando por protocolo: {protocol}")
        filtered_packets = sniffer.filter_by_protocol(protocol)
        sniffer.print_packets(filtered_packets)

    # Filtrar los paquetes si se ha proporcionado un texto
    if text:
        print(Fore.YELLOW + f"[+] Filtrando por texto: {text}")
        filtered_packets = sniffer.filter_by_text(text)
        sniffer.print_packets(filtered_packets)

    # Si se ha solicitado exportar a un archivo .pcap
    if export:
        print(Fore.GREEN + f"[+] Exportando paquetes a: {export}")
        sniffer.export_to_pcap(sniffer.capture_packet, export)

    # Si se solicita mostrar los paquetes capturados
    if display:
        print(Fore.CYAN + "[+] Mostrando paquetes capturados:")
        sniffer.print_packets()


if __name__ == '__main__':
    # Impresion y configuracion de los argumentos
    parser = argparse.ArgumentParser(
        description=f'{Fore.LIGHTBLUE_EX}Desarrollado por: N111X\n{Fore.LIGHTBLUE_EX}Sniffer.',
        formatter_class=argparse.RawTextHelpFormatter,  # Usamos RawTextHelpFormatter para controlar el formato
        add_help=True
    )

    # Argumentos que puede recibir el script
    parser.add_argument("-i", "--interface", help="Interfaz de red para la captura en vivo", type=str,
                        default="Ethernet")
    parser.add_argument("-r", "--read-pcap", help="Importar un archivo .pcap para su analisis", type=str)
    parser.add_argument("-e", "--export-pcap", help="Exportar el analisis en un fichero .pcap", type=str,
                        default="capture.pcap")
    parser.add_argument("-p", "--protocol", help="Filtrar paquetes por un protocolo especifico", type=str)
    parser.add_argument("-t", "--text", help="Filtrar paquetes que contengan un texto especifico", type=str)
    parser.add_argument("-d", "--display", help="Mostrar los paquetes en la terminal", action="store_true")

    args = parser.parse_args()

    # Llamamos a la funcion main con los argumentos parseados
    main(
        interface=args.interface,
        pcapfile=args.read_pcap,
        export=args.export_pcap,
        protocol=args.protocol,
        text=args.text,
        display=args.display
    )