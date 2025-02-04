# Desarrollando un Analizador de Red (Sniffer)

## Introducción

Un sniffer es una herramienta esencial para monitorear y analizar el trafico de red. Permite detectar cuellos de botella, problemas de rendimiento, e incluso interceptar comunicaciones, como mensajes de correo o claves transmitidas en texto plano. Su aplicación es crucial tanto en el ámbito de la administración de redes como en el hacking ético y el análisis de seguridad.

## Instalación

Para poder hacer un sniffer en Python, principalmente haremos uso del modulo externo `pyshark`. Este modulo nos permitira realizar "captura de paquetes en vivo" y analizar "capturas con las que ya contabamos". `pyshark` es un _wrapper_ de `tshark`, por lo que para que funcione correctamente es necesario tener `Wireshark` y `tshark` instalados en el sistema.

### Windows

1. Descarga Wireshark desde [Wireshark](https://www.wireshark.org/download.html) y durante la instalacion asegúrate de marcar la casilla para agregarlo al PATH.
2. Verifica que `tshark` esta correctamente instalado ejecutando en una terminal con permisos de administrador:
    ```cmd
    tshark -v
    ```
    Si recibes un error indicando que `tshark` no es reconocido, deberas agregarlo manualmente al PATH.
3. Descarga python desde [python](https://www.python.org/downloads/), durante la instalación asegúrate de marcar la casilla incluir al PATH.
4. Abre una terminal y verifica si se instalo correctamente con:
	```python
	python
	```
	Esto deberá abrirte una interfaz interactiva, en caso de que te salga algún error con el comando, deberás agregar python al PATH
### Linux

#### 1. **Ubuntu / Debian y derivados**
```bash
sudo apt update
sudo apt install wireshark python
sudo usermod -aG wireshark $USER
```
Luego, cierra sesion y vuelve a iniciarla para aplicar los cambios.

#### 2. **Fedora**
```bash
sudo dnf install wireshark python
sudo usermod -aG wireshark $USER
```
Reinicia la sesion.

#### 3. **Arch Linux / Manjaro**
```bash
sudo pacman -S wireshark-qt python
sudo usermod -aG wireshark $USER
```
Cierra sesion e inicia de nuevo.

#### 4. **openSUSE**
```bash
sudo zypper install wireshark python
sudo usermod -aG wireshark $USER
```
Reinicia la sesion.

#### 5. **CentOS / RHEL**
```bash
sudo yum install epel-release
sudo yum install wireshark-qt python
sudo usermod -aG wireshark $USER
```
Reinicia la sesion.

#### Verificación
Para comprobar que Wireshark esta correctamente instalado:
```bash
wireshark --version
python
```

#### Instalación de `pyshark`
```bash
pip install pyshark
```

Si usas un entorno virtual, realiza la instalación dentro del entorno.

## Funcionamiento General de un Sniffer

Los sniffers capturan paquetes al poner la tarjeta de red en modo promiscuo, permitiendo recibir todo el trafico que circula por la red, no solo el destinado a la propia maquina. Son especialmente efectivos en redes LAN con topologia de bus, donde todo el trafico pasa por un medio comun. En redes conmutadas, su efectividad puede verse reducida, a menos que se utilicen tecnicas como el ARP spoofing.

## Modo Promiscuo

En modo promiscuo, la tarjeta de red deja de filtrar paquetes por direccion IP y comienza a capturar todo el trafico que pasa por la red. En sistemas UNIX/Linux, el estado de la interfaz puede verificarse con `ifconfig`, mientras que en Windows se requieren herramientas especializadas para detectar y activar este modo.

### Activar Modo Promiscuo en Windows

Wireshark utiliza **Npcap** o **WinPcap**, que permiten habilitar el modo promiscuo a nivel del driver de red.

**Pasos para activar el modo promiscuo:**

5. Descarga e instala [Npcap](https://nmap.org/npcap/).
6. Durante la instalacion, selecciona la opcion **"Support raw 802.11 traffic (and monitor mode) for wireless adapters"**.
7. Abre PowerShell como administrador y ejecuta:
    
    ```powershell
    Get-NetAdapter -Name "Ethernet" | Format-List Name,PromiscuousMode
    ```
    
8. Para activar el modo promiscuo:
    
    ```powershell
    Set-NetAdapterAdvancedProperty -Name "Ethernet" -DisplayName "Promiscuous Mode" -DisplayValue "Enabled"
    ```
    
9. Verifica el cambio:
    
    ```powershell
    Get-NetAdapterAdvancedProperty -Name "Ethernet" | Where-Object DisplayName -EQ "Promiscuous Mode"
    ```
    

## Detección de Sniffers en la Red

Se describen tecnicas para detectar sniffers en redes:

- **En redes no conmutadas:** Analizar trafico sospechoso que no deberia estar visible.
- **En redes conmutadas:** Uso de tecnicas de ARP spoofing para redirigir trafico y detectar interceptores.
- **En sistemas UNIX/Linux:** Verificar el modo promiscuo de interfaces.
- **En sistemas Windows:** Utilizar herramientas de diagnostico especializadas como `Netsh` o PowerShell.

## Implementación del Sniffer 

Ahora comenzaremos con la parte mas divertida, programar.
Para ello, yo usare nvim, pero pueden usar el IDE que gusten, el que es mas recomendable para python es Pycharm.

Comencemos con algo sencillo.
Importamos el modulo de `pyshark` para poder trabajar con el.
![Image](https://github.com/user-attachments/assets/5f3b736b-177c-46c8-a889-c6176bb23ccd)
```python
# Crearemos una variable que tiene como valor una lista vacia, esta lista vacia sera la que almacene los resultados, en este caso almacenara los paquetes que iremos capturando
paquetes_captura = []
```
Podemos ver en la documentación de [pyshark](https://github.com/KimiNewt/pyshark/) como comenzar a capturar los paquetes. 
primero debemos crear un objeto, que lo llamaremos `captura` de tipo _LiveCapture_ que estará capturando paquetes en vivo, este objeto puede recibir varios parámetros:
- **param interface**: Name of the interface to sniff on. If not given, takes the first available.
- **param bpf_filter**: BPF filter to use on packets.
- **param display_filter**: Display (wireshark) filter to use.
- **param only_summaries**: Only produce packet summaries, much faster but includes very little information
- **param disable_protocol**: Disable detection of a protocol (tshark > version 2)
- **param decryption_key**: Key used to encrypt and decrypt captured traffic.
- **param encryption_type**: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or 'WPA-PWK'. Defaults to WPA-PWK).
- **param tshark_path**: Path of the tshark binary
- **param output_file**: Additionally save captured packets to this file.

De momento solo utilizaremos el parámetro de `inerface=` en donde especificaremos en ID de nuestra tarjeta de red, en caso de que no sepan el ID o nombre de la tarjeta de red, desde una terminal en windows o linux con el comando:
```cdm/shell
tshark -D
```
podrán ver las interfaces que tienen y elegir la correcta.

Entonces:
```python
# Entonces la linea completa nos quedaria asi.
# Al especificar la interfaz podemos hacerlo con el ID o poniendo el nombre completo.
capture = pyshark.LiveCapture(interfaces="6")
```
Después de esto solo imprimimos unos mensajes de ayuda para que el usuario sepa que la captura ah comenzado.
Ahora necesitamos almacenar los resultados dentro de nuestra lista para poder imprimirlos después.
Debemos saber que hay dos maneras de capturas los paquetes podemos utilizar el método `sniff()` o el método `sniff_contiously()`. El uso de uno de estos métodos dependerá de nuestros objetivos, en nuestro caso utilizaremos `sniff_contiously()` para realizar la captura continua y poder almacenar los paquetes, para ello utilizaremos un bucle for:
```python
# De esta manera almacenamos los paquetes para poder trabajar mejor con ellos despues.
for paquete in capturan.sniffer_contiously():
	paquetes_captura.append(paquetes)
```
Después en el momento que presionemos `ctrl + c` saltara una excepción entonces la manejamos para que imprima el mensaje que la captura a terminado.

Por ultimo solo necesitamos imprimir lo que almacenamos en la variable `paquetes_captura`, también lo haremos con ayuda de un for:
```python
for pkt in paquetes_captura:
	print("-" * 474) # Esta linea unicamente nos ayuda a
	# imprimir una separacion para identi cada paquete
	print(str(pkt)) # COnvertimos los paquetes a cadenas
	# (strings) para poder imprimirlas. 
```


La salida se ve algo de esta manera:

![Image](https://github.com/user-attachments/assets/5bc63169-06ec-45b0-a4d1-2933ab5854b1)

## Detección de un sniffer en al Red.
### Detección de Sniffers en sistemas UNIX/Linux

1. **Test DNS**:  
    Puedes crear conexiones TCP falsas en tu red, esperando que un sniffer mal escrito las capture. Algunos sniffers realizan búsquedas inversas DNS, y si detectas una petición de resolución de direcciones IP inexistentes, puedes identificar que un sniffer está activo.
    
2. **Test del Ping**:  
    Envías un "ICMP echo" (ping) con una dirección MAC incorrecta hacia la máquina sospechosa. Si la máquina está en modo promiscuo, el sniffer capturará el paquete y responderá, lo que indica que está funcionando.
    
3. **Test ICMP - Ping de Latencia**:  
    Haces un ping al objetivo y mides el tiempo de latencia (RTT). Luego, generas conexiones TCP falsas rápidamente. Si el sniffer está procesando los paquetes, notarás un aumento en el RTT. Comparando el tiempo de latencia antes y después, podrás saber si un sniffer está activo.
    
4. **Test ARP**:  
    Envías una petición ARP con una dirección MAC incorrecta. Si la máquina está en modo promiscuo, responderá, lo que te indica que un sniffer está capturando el tráfico de red.
    
5. **Test Etherping**:  
    Envías un "ping echo" con la dirección IP correcta y una dirección MAC falsificada. Si el host responde, significa que su interfaz está en modo promiscuo y que hay un sniffer activo.

### Detección de Sniffers en Sistemas Windows

1. **PROMISCAN**:  
    **PromiScan** es una herramienta gratuita que permite localizar rápidamente los nodos promiscuos en una red LAN sin generar una carga significativa. Aunque la tarea de detectar un nodo promiscuo puede ser difícil y los resultados no siempre son precisos, **PromiScan** muestra estos nodos de manera clara y visible. Para usarla, necesitas Windows 2000 Professional y tener instalado el controlador WinPcap.
    
2. **PROMISDETECT**:  
    **PromisDetect** es otra utilidad que te ayuda a detectar nodos en modo promiscuo en tu red, y está disponible para su descarga desde su página oficial.
    
3. **ProDETECT 0.2 BETA**:  
    **ProDETECT** es una herramienta de detección que está en su versión beta. Permite identificar posibles sniffers en tu red y está disponible en SourceForge.
    

### Detección en Redes Conmutadas

En redes conmutadas (que usan switches), una técnica común para detectar sniffers es el **ARP poisoning** (envenenamiento ARP). Esto implica modificar la tabla ARP de los dispositivos para redirigir las tramas hacia la MAC del atacante, permitiéndole capturar las comunicaciones. Para prevenirlo, se puede usar **MACs estáticas**, aunque no es completamente efectivo en algunos sistemas Windows.

4. **ARPWatch**:  
    **ARPWatch** es una herramienta para sistemas Linux que detecta el uso de envenenamiento ARP. Compara las direcciones IP con las MAC y envía alertas cuando se detecta un cambio en la tabla ARP.
    
5. **WinARP Watch v1.0**:  
    **WinARP Watch** es una herramienta similar a **ARPWatch** pero diseñada para Windows. Monitorea la caché ARP y las correspondencias IP/MAC, y te mantiene informado sobre cualquier nuevo par que se añada a la red, aunque no envía correos de alerta.


Este articulo es únicamente con el fin de trata de explicar como es que funciona un sniffer y mencionar algunos métodos para poder identificar un sniffer en la red. Además, se han descrito algunas herramientas y métodos tanto para la detección en sistemas UNIX/Linux como en Windows, así como en redes conmutadas, lo que te permitirá estar mejor preparado para identificar posibles amenazas y proteger tu red de intrusos que puedan estar interceptando el tráfico. El artículo también proporciona una guía básica para la implementación de un sniffer en Python, ayudándote a entender su funcionamiento y cómo capturar paquetes para su posterior análisis. Es una herramientas mas para la comprension que para el uso en algun entorno real, en su caso recomiendo usar Wireshark o tshark.
