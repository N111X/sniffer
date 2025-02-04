from colorama import Fore, init  # Modulo para la impresion con colores, facilita la visualizacion en la terminal
from scapy.all import wrpcap  # Modulo de Scapy para escribir paquetes a un archivo pcap
from scapy.layers.l2 import Ether  # Modulo de Scapy para tratar con paquetes Ethernet
import pyshark  # Modulo para captura de paquetes y analisis de trafico de red

init(autoreset=True)  # Inicializa el colorama para resetear los colores automaticamente despues de cada impresion

class Sniffer:
    """
    Esta clase permite la captura, filtrado, exportacion e impresion de paquetes de red.
    Se compone de varias funciones para interactuar con el trafico de red en tiempo real o desde un archivo.
    """

    def __init__(self):
        """
        Funcion constructora de la clase Sniffer.
        Inicializa los atributos necesarios para la captura y almacenamiento de paquetes.
        """
        self.capture = None  # Objeto para realizar la captura de paquetes
        self.capture_packet = []  # Lista que contendra los paquetes capturados

    def capture_live(self, interface="Ethernet", display_filter=""):
        """
        Esta funcion realiza la captura de paquetes en tiempo real.
        Permite especificar una interfaz y aplicar filtros de captura BPF.

        :param interface: Define la interfaz de red que se utilizara para la captura, por defecto es 'Ethernet'.
        :param display_filter: Permite aplicar filtros a la captura usando el formato BPF (Berkeley Packet Filter).
        """
        try:
            # Inicia la captura en tiempo real, con los filtros especificados
            self.capture = pyshark.LiveCapture(
                interface=interface,
                display_filter=display_filter,
                use_json=True,
                include_raw=True  # Incluye los datos crudos (hexadecimal) de cada paquete
            )
            # Mensaje informando que la captura ha comenzado
            print(Fore.BLUE + "[+] Captura de paquetes iniciada" +
                  Fore.RED + "\nPresione CTRL + C para salir.")

            # Captura continuamente los paquetes y los almacena en la lista
            for packet in self.capture.sniff_continuously():
                self.capture_packet.append(packet)  # Anade el paquete capturado a la lista

        except (KeyboardInterrupt, EOFError):
            # Captura interrumpida por el usuario (CTRL + C)
            print(Fore.RED + f"[!] Captura terminada (Total de paquetes: {len(self.capture_packet)}).")

    def import_capture(self, pcapfile, display_filter=""):
        """
        Esta funcion importa una captura de un archivo .pcap ya existente para analizarla.

        :param pcapfile: Ruta del archivo .pcap que se desea importar.
        :param display_filter: Filtro BPF que se aplica a los paquetes importados.
        """
        try:
            # Inicia la lectura del archivo pcap
            self.capture = pyshark.FileCapture(
                input_file=pcapfile,
                display_filter=display_filter,
                keep_packets=False  # No guarda los paquetes, solo los procesa
            )
            # Almacena los paquetes leidos en la lista
            self.capture_packet = [pkt for pkt in self.capture]
            print(Fore.GREEN + f"Lectura de {pcapfile} correcta.")

        except Exception as e:
            # En caso de error al leer el archivo
            print(Fore.RED + f"Error al leer {pcapfile} : {e}")

    @staticmethod
    def export_to_pcap(packets, filename='capture.pcap'):
        """
        Esta funcion exporta los paquetes capturados a un archivo .pcap para su posterior analisis.

        :param packets: Lista de paquetes que se exportaran.
        :param filename: Nombre del archivo .pcap donde se guardaran los paquetes. Por defecto es 'capture.pcap'.
        """
        # Convierte los paquetes de pyshark a formato de Scapy (Ethernet)
        scapy_packets = [Ether(pkt.get_raw_packet()) for pkt in packets]
        wrpcap(filename, scapy_packets)  # Escribe los paquetes en el archivo .pcap
        print(Fore.BLUE + f"[+] Paquetes guardados en {filename}")

    def filter_by_protocol(self, protocolo):
        """
        Filtra los paquetes capturados segun un protocolo especifico.

        :param protocolo: Protocolo por el que se desea filtrar los paquetes.
        :return: Lista de paquetes que coinciden con el protocolo especificado.
        """
        # Filtra los paquetes que contienen el protocolo especificado
        filter_packets = [packet for packet in self.capture_packet if protocolo in packet]
        return filter_packets

    def filter_by_text(self, text):
        """
        Filtra los paquetes que contienen un texto especifico en cualquiera de sus capas.
 
        :param text: Texto a buscar dentro de los paquetes capturados.
        :return: Lista de paquetes que contienen el texto.
        """
        filter_text = []  # Lista donde se almacenaran los paquetes que coinciden con el texto
        for packet in self.capture_packet:
            # Recorre todas las capas de cada paquete
            for layer in packet.layers:
                # Recorre todos los campos de la capa
                for fiel_line in layer._get_all_field_lines():
                    if text in fiel_line:  # Si el texto se encuentra en el campo, anade el paquete a la lista
                        filter_text.append(packet)
                        break
        return filter_text

    def print_packets(self, packets=None):
        """
        Imprime todos los paquetes capturados o los proporcionados como argumento.

        :param packets: Lista de paquetes a imprimir. Si no se proporciona, se usan los paquetes capturados.
        """
        if packets is None:
            packets = self.capture_packet  # Si no se pasan paquetes, imprime los capturados

        # Recorre e imprime cada paquete en la lista
        for packet in packets:
            print(packet)
            print(Fore.YELLOW + "-" * 474)
