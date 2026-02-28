# VTP-Attacks
📌 Autor
Nombre: Gerson Javier Pérez Reyes
Matrícula: 20241529
Asignatura: Seguridad de Redes

# 🎯 Objetivo del Script

El objetivo de esta herramienta es demostrar la explotación del protocolo VTP (VLAN Trunking Protocol) mediante:

✔ Agregado no autorizado de una VLAN

✔ Eliminación de VLANs existentes

El ataque se realiza enviando anuncios VTP falsificados para modificar la base de datos de VLANs del dominio.

# 🧠 Descripción Técnica

VTP es un protocolo propietario de Cisco que permite la administración centralizada de VLANs dentro de un dominio.

Si un atacante introduce un switch con:

Mismo nombre de dominio VTP

Mayor número de revisión

Modo Server

Puede sobrescribir la base de datos de VLANs en toda la red.

# Topología Utilizada

<img width="1242" height="501" alt="image" src="https://github.com/user-attachments/assets/97eb27f4-8c85-4e2e-98fd-b856d7a6fd9b" />

VLANs Configuradas
VLAN	Red
10	10.15.29.0/24
20	10.15.30.0/24

# Parámetros Utilizados

Framework principal: Scapy

Interfaz atacante: eth0

Dominio VTP: ITLA

Modo VTP: Server

Versión: VTP v2

Requisitos

Kali Linux

Python 3

Scapy

Acceso a red troncal

Dominio VTP activo

Switches Cisco en modo Server/Client

Instalación:
sudo apt install python3-scapy

🚨 Ataques Realizados
1️⃣ Agregado de VLAN

Se envió un anuncio VTP con:

Número de revisión superior

Nueva VLAN 99

Resultado:
La VLAN fue propagada automáticamente a los switches del dominio.

2️⃣ Eliminación de VLAN

Se envió un anuncio VTP con:

Base de datos vacía

Número de revisión mayor

Resultado:
Las VLANs fueron eliminadas de la red.

# Evidencias

Captura antes del ataque

Captura después del ataque

show vlan brief

debug vtp events

# Medidas de Mitigación

Para proteger la red contra VTP Attacks se implementaron las siguientes medidas:

✔ Configurar VTP en modo Transparent
vtp mode transparent
✔ Configurar contraseña VTP
vtp password ciberseguro
✔ Deshabilitar DTP en troncales
switchport nonegotiate
✔ Configurar manualmente los troncales
switchport mode trunk
✔ Limitar acceso físico

Control de puertos

Port-Security

✔ Deshabilitar puertos no utilizados
interface range e0/10-24
shutdown
