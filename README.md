# IPSec VPN — Basado en Políticas (IKEv2)

### Jordy Jose Rosario Ortiz · Matrícula: 2025-0737

**Seguridad de Redes 2026-C-2 · ITLA**

---

## 📋 Tabla de Contenido

1. [Objetivo del Laboratorio](#1-objetivo-del-laboratorio)
2. [Marco Teórico](#2-marco-teórico)
   - [¿Qué es IKEv2?](#21-qué-es-ikev2)
   - [Negociación IKEv2 — IKE_SA_INIT e IKE_AUTH](#22-negociación-ikev2--ike_sa_init-e-ike_auth)
   - [IKEv1 vs. IKEv2](#23-ikev1-vs-ikev2)
   - [Parámetros Criptográficos Utilizados](#24-parámetros-criptográficos-utilizados)
3. [Documentación de la Red](#3-documentación-de-la-red)
   - [Topología](#31-topología)
   - [Tabla de Dispositivos y Direccionamiento IP](#32-tabla-de-dispositivos-y-direccionamiento-ip)
4. [Scripts de Configuración](#4-scripts-de-configuración)
   - [Router R1 — Site A](#41-router-r1--site-a)
   - [Router R2 — Site B](#42-router-r2--site-b)
   - [Configuración de PCs (Hosts)](#43-configuración-de-pcs-hosts)
5. [Verificación del Túnel](#5-verificación-del-túnel)
6. [Capturas de Pantalla](#6-capturas-de-pantalla)
7. [Consideraciones de Seguridad](#7-consideraciones-de-seguridad)
8. [Video Demostrativo](#8-video-demostrativo)
9. [Referencias](#9-referencias)

---

## 1. Objetivo del Laboratorio

El objetivo de este laboratorio es **implementar y verificar una VPN Site-to-Site basada en políticas utilizando IPSec con IKEv2** sobre infraestructura Cisco IOS. A través de esta práctica se busca demostrar:

* La configuración del protocolo IKEv2 (RFC 7296) mediante los objetos propios de su arquitectura en Cisco IOS: `crypto ikev2 proposal`, `crypto ikev2 policy`, `crypto ikev2 keyring` y `crypto ikev2 profile` — reemplazando completamente el bloque `crypto isakmp` de IKEv1.
* La protección criptográfica del tráfico de datos entre dos subredes LAN privadas (`20.25.37.128/25` y `20.25.37.0/25`) a través de un segmento de red pública simulado (`192.168.1.0/24`).
* El uso de **Crypto Maps** y **ACLs de tráfico interesante** como mecanismo de selección de flujos a cifrar, manteniendo el modelo *policy-based* pero con IKEv2 como protocolo de negociación.
* La diferencia práctica entre la jerarquía de configuración de IKEv1 y la de IKEv2, y las ventajas que aporta IKEv2 en cuanto a eficiencia, seguridad y capacidades modernas.

---

## 2. Marco Teórico

### 2.1 ¿Qué es IKEv2?

IKEv2 (Internet Key Exchange version 2 — RFC 7296) es el protocolo de gestión de claves moderno que reemplaza a IKEv1 (RFC 2409). Fue diseñado para corregir las limitaciones de su predecesor manteniendo el mismo propósito: automatizar el establecimiento de las **Security Associations (SAs)** entre dos peers IPSec de forma segura y autenticada.

IKEv2 introduce mejoras fundamentales sobre IKEv1:

* **Negociación más eficiente:** IKEv2 establece el canal seguro y negocia las SAs IPSec en **4 mensajes** (2 intercambios de request/response), frente a los 9 mensajes mínimos de IKEv1 (6 en Main Mode + 3 en Quick Mode).
* **Soporte nativo de EAP:** IKEv2 puede autenticar usuarios finales mediante EAP (Extensible Authentication Protocol) — fundamental para VPNs de acceso remoto con usuario y contraseña.
* **MOBIKE (RFC 4555):** Extensión de IKEv2 que permite que un peer cambie su dirección IP sin perder el túnel establecido — esencial para clientes móviles y conexiones multihomed.
* **Dead Peer Detection incorporado:** IKEv2 tiene detección de peers caídos integrada en el protocolo (mensajes keepalive), sin necesidad de configurarla por separado como en IKEv1.
* **Traffic Selectors negociados:** En lugar de ACLs que definen el tráfico interesante de forma estática, IKEv2 negocia los **Traffic Selectors (TS)** durante el intercambio, ofreciendo mayor flexibilidad.
* **Resistencia a ataques DoS:** IKEv2 introduce un mecanismo de cookie anti-spoofing (IKEv2 Cookie Challenge) que protege al servidor de ataques de denegación de servicio durante la negociación.

### 2.2 Negociación IKEv2 — IKE_SA_INIT e IKE_AUTH

A diferencia de IKEv1 con sus dos fases separadas, IKEv2 unifica la negociación en **dos intercambios** (cuatro mensajes en total):

#### Intercambio 1 — IKE_SA_INIT

Objetivo: establecer el canal IKE cifrado negociando los parámetros criptográficos e intercambiando material de clave Diffie-Hellman.

| Mensaje | Dirección | Contenido |
|---|---|---|
| Request (msg 1) | Iniciador → Respondedor | Propuesta de algoritmos (SA), valores DH (KEi), nonce (Ni) |
| Response (msg 2) | Respondedor → Iniciador | Propuesta aceptada (SA), valores DH (KEr), nonce (Nr), certificado opcional |

Al finalizar este intercambio, ambos peers han derivado las claves simétricas del canal IKE. **Todos los mensajes siguientes viajan cifrados.**

#### Intercambio 2 — IKE_AUTH

Objetivo: autenticar los peers y negociar las Child SAs (equivalentes a las IPSec SAs de IKEv1 Fase 2).

| Mensaje | Dirección | Contenido |
|---|---|---|
| Request (msg 3) | Iniciador → Respondedor | Identidad del iniciador (IDi), autenticación (AUTH), Traffic Selectors (TSi, TSr), propuesta Child SA |
| Response (msg 4) | Respondedor → Iniciador | Identidad del respondedor (IDr), autenticación (AUTH), Traffic Selectors aceptados, Child SA confirmada |

El resultado son las **Child SAs** — las SAs IPSec bidireccionales que protegen el tráfico de datos. A diferencia de IKEv1 que creaba las IPSec SAs en Quick Mode separado, IKEv2 las crea **dentro del mismo intercambio de autenticación**.

### 2.3 IKEv1 vs. IKEv2

| Característica | IKEv1 (lab anterior) | IKEv2 (este lab) |
|---|---|---|
| **RFC** | RFC 2409 (1998) | RFC 7296 (2014) |
| **Mensajes de negociación** | 9 mínimo (6 MM + 3 QM) | 4 (2 IKE_SA_INIT + 2 IKE_AUTH) |
| **Fases** | Fase 1 (ISAKMP SA) + Fase 2 (IPSec SA) | IKE SA + Child SA (en un solo flujo) |
| **Autenticación EAP** | No nativo | ✅ Soportado |
| **MOBIKE** | ❌ No | ✅ Sí (RFC 4555) |
| **Dead Peer Detection** | Configuración separada (DPD) | ✅ Integrado |
| **Resistencia a DoS** | Baja | ✅ Cookie Challenge |
| **Comando principal Cisco IOS** | `crypto isakmp policy` | `crypto ikev2 proposal` |
| **Perfil de autenticación** | `crypto isakmp key` | `crypto ikev2 keyring` + `crypto ikev2 profile` |
| **Vinculación al túnel** | `crypto map` en interfaz WAN | `crypto map` + `set ikev2-profile` |
| **Estado recomendado** | Legacy — en desuso | ✅ Estándar actual |

En Cisco IOS, IKEv1 e IKEv2 coexisten en el mismo router. La diferencia está en el bloque de configuración: `crypto isakmp` para IKEv1 y `crypto ikev2` para IKEv2. El Transform Set y la Crypto Map son **compartidos** entre ambas versiones.

### 2.4 Parámetros Criptográficos Utilizados

| Parámetro | Valor configurado | Propósito |
|---|---|---|
| **Cifrado IKE SA** | AES-256-CBC | Cifrado del canal IKE |
| **Integridad IKE SA** | SHA-256 | Integridad de los mensajes IKE |
| **Grupo Diffie-Hellman** | Grupo 14 (2048-bit MODP) | Intercambio seguro de material de clave |
| **PRF (Pseudo-Random Function)** | SHA-256 | Derivación de claves simétricas |
| **Autenticación** | Pre-Shared Key (PSK) | Autenticación mutua de los peers |
| **Lifetime IKE SA** | 86400 segundos (24 horas) | Duración del canal IKE antes de renegociar |
| **Cifrado ESP (Child SA)** | AES-256 | Cifrado del tráfico de datos |
| **Autenticación ESP (Child SA)** | SHA-256 HMAC | Integridad del tráfico de datos |
| **Modo IPSec** | Tunnel | VPN Site-to-Site completa |
| **Lifetime Child SA** | 3600 segundos (1 hora) | Duración del túnel de datos antes de renegociar |

---

## 3. Documentación de la Red

### 3.1 Topología

El laboratorio simula la interconexión segura de dos sitios corporativos a través de Internet. El segmento `192.168.1.0/24` representa la nube pública/ISP. Las subredes LAN privadas están derivadas de la matrícula `20250737`. A diferencia del laboratorio IKEv1, el protocolo de negociación es IKEv2 — el modelo de selección de tráfico (Crypto Map + ACL) se mantiene igual.

```
                              [ INTERNET / ISP ]
                              192.168.1.0/24
                              (Router ISP: 192.168.1.2)
                                    │
                   ┌────────────────┴────────────────┐
                   │ e0/0: 192.168.1.10              │ e0/0: 192.168.1.20
           ┌───────┴───────┐                 ┌───────┴───────┐
           │  Router R1    │◄═══ TÚNEL ══════►  Router R2    │
           │  (Site A)     │   IPSec IKEv2   │  (Site B)     │
           └───────┬───────┘  Policy-Based   └───────┬───────┘
                   │ e0/1: 20.25.37.129/25           │ e0/1: 20.25.37.1/25
                   │                                 │
           ┌───────┴───────┐                 ┌───────┴───────┐
           │  Switch SW1   │                 │  Switch SW2   │
           └───┬───────┬───┘                 └───┬───────┬───┘
               │       │                         │       │
           ┌───┴──┐ ┌──┴───┐               ┌────┴─┐ ┌───┴──┐
           │ PC1  │ │ PC2  │               │ PC3  │ │ PC4  │
           │.130  │ │.131  │               │ .2   │ │ .3   │
           └──────┘ └──────┘               └──────┘ └──────┘
            20.25.37.128/25                 20.25.37.0/25
               SITE A                          SITE B

  ════════════════════════════════════════════════════════════════
  Flujo del túnel IPSec IKEv2:
    1. PC1 (20.25.37.130) hace ping a PC3 (20.25.37.2).
    2. R1 detecta tráfico interesante (ACL_IPSEC_TRAFFIC).
    3. R1 inicia IKE_SA_INIT con R2 — 2 mensajes (algoritmos + DH).
    4. IKE_AUTH — 2 mensajes: autenticación PSK + Child SA IPSec.
    5. Total: 4 mensajes (vs. 9 de IKEv1). Túnel listo.
    6. El tráfico viaja cifrado: 192.168.1.10 → 192.168.1.20.
    7. R2 desencapsula y entrega a PC3. Conexión segura establecida.
  ════════════════════════════════════════════════════════════════
```

### 3.2 Tabla de Dispositivos y Direccionamiento IP

| Dispositivo | Tipo / Modelo | Interfaz | Dirección IP | Máscara | Gateway | Rol |
|---|---|---|---|---|---|---|
| **ISP** | Router ISP | e0/0 | 192.168.1.2 | /24 | — | Enlace hacia R1 |
| | | e0/1 | 192.168.1.2 | /24 | — | Enlace hacia R2 |
| **R1** | Cisco IOS (Router) | e0/0 | 192.168.1.10 | /24 | 192.168.1.2 | Gateway WAN — Site A |
| | | e0/1 | 20.25.37.129 | /25 | — | Gateway LAN — Site A |
| **R2** | Cisco IOS (Router) | e0/0 | 192.168.1.20 | /24 | 192.168.1.2 | Gateway WAN — Site B |
| | | e0/1 | 20.25.37.1 | /25 | — | Gateway LAN — Site B |
| **SW1** | Cisco IOS (Switch L2) | — | — | — | — | Conmutación LAN Site A |
| **SW2** | Cisco IOS (Switch L2) | — | — | — | — | Conmutación LAN Site B |
| **PC1** | Host Linux / VPC | eth0 | 20.25.37.130 | /25 | 20.25.37.129 | Host Site A |
| **PC2** | Host Linux / VPC | eth0 | 20.25.37.131 | /25 | 20.25.37.129 | Host Site A |
| **PC3** | Host Linux / VPC | eth0 | 20.25.37.2 | /25 | 20.25.37.1 | Host Site B |
| **PC4** | Host Linux / VPC | eth0 | 20.25.37.3 | /25 | 20.25.37.1 | Host Site B |

---

## 4. Scripts de Configuración

### 4.1 Router R1 — Site A

```cisco
! ══════════════════════════════════════════════════════
! R1 — Site A | IPSec IKEv2 Policy-Based VPN
! Jordy Rosario — 20250737 | Seguridad de Redes 2026-C-2
! ══════════════════════════════════════════════════════

hostname R1

! ─── Interfaces ────────────────────────────────────────
interface Ethernet0/0
 description WAN-hacia-ISP
 ip address 192.168.1.10 255.255.255.0
 no shutdown

interface Ethernet0/1
 description LAN-SiteA
 ip address 20.25.37.129 255.255.255.128
 no shutdown

! ─── Ruta por defecto hacia Internet (ISP) ─────────────
ip route 0.0.0.0 0.0.0.0 192.168.1.2

! ══════════════════════════════════════════════════════
! BLOQUE IKEv2 — reemplaza completamente a crypto isakmp
! ══════════════════════════════════════════════════════

! ─── PASO 1: IKEv2 Proposal ────────────────────────────
! Define los algoritmos criptográficos del canal IKE SA.
! Equivalente a: crypto isakmp policy en IKEv1.
crypto ikev2 proposal PROP_IKEv2
 encryption aes-cbc-256
 integrity sha256
 group 14
! NOTA: el comando "prf" no está disponible en IOSv/IOS 15.x.
! IOS deriva el PRF automáticamente del algoritmo de integridad (SHA256).
! Solo agregar "prf" si el equipo corre IOS-XE 16.x o superior y lo acepta.

! ─── PASO 2: IKEv2 Policy ──────────────────────────────
! Vincula el Proposal a una política global.
! En IKEv1 la policy incluía todo; en IKEv2 está separado.
crypto ikev2 policy POL_IKEv2
 proposal PROP_IKEv2

! ─── PASO 3: IKEv2 Keyring ─────────────────────────────
! Define las pre-shared keys por peer.
! Equivalente a: crypto isakmp key en IKEv1.
crypto ikev2 keyring KR_SITEB
 peer R2_SITEB
  address 192.168.1.20
  pre-shared-key local  JordyITLA2026!
  pre-shared-key remote JordyITLA2026!

! ─── PASO 4: IKEv2 Profile ─────────────────────────────
! Une la política de matching con el keyring y la identidad.
! No existe equivalente directo en IKEv1 — es nuevo en IKEv2.
crypto ikev2 profile PROF_IKEv2
 match identity remote address 192.168.1.20 255.255.255.255
 authentication local pre-share
 authentication remote pre-share
 keyring local KR_SITEB

! ══════════════════════════════════════════════════════
! BLOQUE IPSEC — idéntico al de IKEv1, pero vincula IKEv2
! ══════════════════════════════════════════════════════

! ─── PASO 5: Transform Set ─────────────────────────────
! Define cifrado y autenticación del tráfico de datos (ESP).
! Igual que en IKEv1.
crypto ipsec transform-set TS_AES256_SHA256 esp-aes 256 esp-sha256-hmac
 mode tunnel

! ─── PASO 6: ACL — Tráfico Interesante ─────────────────
! Define qué flujos IP activan y son protegidos por IPSec.
ip access-list extended ACL_IPSEC_TRAFFIC
 permit ip 20.25.37.128 0.0.0.127 20.25.37.0 0.0.0.127

! ─── PASO 7: Crypto Map ────────────────────────────────
! Vincula el Transform Set, la ACL y el IKEv2 Profile.
! La diferencia clave vs IKEv1: se agrega "set ikev2-profile".
crypto map CMAP_SITEA 10 ipsec-isakmp
 description Tunel-IPSec-IKEv2-hacia-SiteB-R2
 set peer 192.168.1.20
 set transform-set TS_AES256_SHA256
 set ikev2-profile PROF_IKEv2
 match address ACL_IPSEC_TRAFFIC
 set security-association lifetime seconds 3600

! ─── PASO 8: Aplicar Crypto Map a interfaz WAN ─────────
interface Ethernet0/0
 crypto map CMAP_SITEA
```

### 4.2 Router R2 — Site B

```cisco
! ══════════════════════════════════════════════════════
! R2 — Site B | IPSec IKEv2 Policy-Based VPN
! Jordy Rosario — 20250737 | Seguridad de Redes 2026-C-2
! ══════════════════════════════════════════════════════

hostname R2

! ─── Interfaces ────────────────────────────────────────
interface Ethernet0/0
 description WAN-hacia-ISP
 ip address 192.168.1.20 255.255.255.0
 no shutdown

interface Ethernet0/1
 description LAN-SiteB
 ip address 20.25.37.1 255.255.255.128
 no shutdown

! ─── Ruta por defecto hacia Internet (ISP) ─────────────
ip route 0.0.0.0 0.0.0.0 192.168.1.2

! ─── PASO 1: IKEv2 Proposal ────────────────────────────
crypto ikev2 proposal PROP_IKEv2
 encryption aes-cbc-256
 integrity sha256
 group 14

! ─── PASO 2: IKEv2 Policy ──────────────────────────────
crypto ikev2 policy POL_IKEv2
 proposal PROP_IKEv2

! ─── PASO 3: IKEv2 Keyring ─────────────────────────────
crypto ikev2 keyring KR_SITEA
 peer R1_SITEA
  address 192.168.1.10
  pre-shared-key local  JordyITLA2026!
  pre-shared-key remote JordyITLA2026!

! ─── PASO 4: IKEv2 Profile ─────────────────────────────
crypto ikev2 profile PROF_IKEv2
 match identity remote address 192.168.1.10 255.255.255.255
 authentication local pre-share
 authentication remote pre-share
 keyring local KR_SITEA

! ─── PASO 5: Transform Set ─────────────────────────────
crypto ipsec transform-set TS_AES256_SHA256 esp-aes 256 esp-sha256-hmac
 mode tunnel

! ─── PASO 6: ACL — Tráfico Interesante ─────────────────
! La ACL debe ser el ESPEJO exacto de la ACL en R1.
ip access-list extended ACL_IPSEC_TRAFFIC
 permit ip 20.25.37.0 0.0.0.127 20.25.37.128 0.0.0.127

! ─── PASO 7: Crypto Map ────────────────────────────────
crypto map CMAP_SITEB 10 ipsec-isakmp
 description Tunel-IPSec-IKEv2-hacia-SiteA-R1
 set peer 192.168.1.10
 set transform-set TS_AES256_SHA256
 set ikev2-profile PROF_IKEv2
 match address ACL_IPSEC_TRAFFIC
 set security-association lifetime seconds 3600

! ─── PASO 8: Aplicar Crypto Map a interfaz WAN ─────────
interface Ethernet0/0
 crypto map CMAP_SITEB
```

### 4.3 Configuración de PCs (Hosts)

**PC1 y PC2 — Site A (`20.25.37.128/25`)**

```bash
# PC1
ip 20.25.37.130 255.255.255.128 20.25.37.129

# PC2
ip 20.25.37.131 255.255.255.128 20.25.37.129
```

**PC3 y PC4 — Site B (`20.25.37.0/25`)**

```bash
# PC3
ip 20.25.37.2 255.255.255.128 20.25.37.1

# PC4
ip 20.25.37.3 255.255.255.128 20.25.37.1
```

> **Nota:** Si los hosts son VPCs de PNETLab se usa el comando `ip` como se muestra. Si son máquinas Linux se configura con `ip addr add` e `ip route add default via`.

---

## 5. Verificación del Túnel

### 5.1 Disparar la negociación IKEv2 (paso obligatorio)

> **IKEv2 es lazy por defecto**, el túnel **no se negocia automáticamente** al aplicar la configuración. La SA se crea únicamente cuando hay tráfico interesante que la dispara. Si se ejecuta `show crypto ikev2 sa` sin haber generado tráfico, el comando devuelve vacío aunque la configuración esté correcta.

Para disparar la negociación, ejecutar un ping desde una red LAN hacia la otra. Desde R1 se puede hacer un ping extendido simulando origen en la LAN del Site A:

```cisco
R1# ping 20.25.37.2 source 20.25.37.129 repeat 5
```

Una vez que el ping genera tráfico interesante, la negociación IKEv2 ocurre en background (4 mensajes: IKE_SA_INIT + IKE_AUTH) y la SA queda establecida.

---

### 5.2 Verificar el estado de la IKEv2 SA

En IKEv2 el comando de verificación principal cambia de `show crypto isakmp sa` a `show crypto ikev2 sa`:

```cisco
R1# show crypto ikev2 sa
```

*Salida esperada — túnel activo:*

```
 IPv4 Crypto IKEv2  SA

Tunnel-id Local                 Remote                fvrf/ivrf            Status
1         192.168.1.10/500      192.168.1.20/500      none/none            READY
      Encr: AES-CBC, keysize: 256, PRF: HMAC-SHA256, Hash: SHA256, DH Grp:14, Auth sign: PSK, Auth verify: PSK
      Life/Active Time: 86400/142 sec
```

> El estado `READY` en IKEv2 equivale al `QM_IDLE` de IKEv1 — indica que la IKE SA está establecida y lista. La línea `Encr/PRF/Hash/DH Grp` confirma los parámetros negociados.

---

### 5.3 Verificar detalles completos de la IKEv2 SA

```cisco
R1# show crypto ikev2 sa detail
```

*Salida esperada (IOSv):*

```
 IPv4 Crypto IKEv2  SA
Tunnel-id Local                 Remote                fvrf/ivrf            Status
1         192.168.1.10/500      192.168.1.20/500      none/none            READY
      Encr: AES-CBC, keysize: 256, Hash: SHA256, DH Grp:14, Auth sign: PSK, Auth verify: PSK
      Life/Active Time: 86400/39 sec
      CE id: 1001, Session-id: 1
      Status Description: Negotiation done
      Local spi: 7B2D42E1991622C1       Remote spi: 92E698E3FE3CCE34
      Local id: 192.168.1.10
      Remote id: 192.168.1.20
      DPD configured for 0 seconds, retry 0
      NAT-T is not detected
      Initiator of SA : Yes
```

> **Nota sobre IOSv:** En esta versión de IOS la sección `Child SA` no aparece en el output de `show crypto ikev2 sa detail`. Eso es normal — los selectores de tráfico y los SPIs de ESP se visualizan con `show crypto ipsec sa` (sección 5.4).

---

### 5.4 Verificar las IPSec SAs (Child SAs)

```cisco
R1# show crypto ipsec sa
```

*Salida esperada (fragmento):*

```
interface: Ethernet0/0
    Crypto map tag: CMAP_SITEA, local addr 192.168.1.10

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (20.25.37.128/255.255.255.128/0/0)
   remote ident (addr/mask/prot/port): (20.25.37.0/255.255.255.128/0/0)
   current_peer 192.168.1.20 port 500
    PERMIT, flags={origin_is_acl,}

    #pkts encaps: 30, #pkts encrypt: 30, #pkts digest: 30
    #pkts decaps: 30, #pkts decrypt: 30, #pkts verify: 30
```

> Los contadores `#pkts encaps/decaps` deben incrementarse con cada ping entre hosts. Este comando es idéntico al de IKEv1 — la Child SA de IKEv2 produce el mismo resultado a nivel IPSec.

---

### 5.5 Verificar la estadística de sesión IKEv2

```cisco
R1# show crypto ikev2 session
```

---

### 5.6 Verificar conectividad extremo a extremo

Ejecutar desde **PC1** hacia **PC3**:

```bash
PC1> ping 20.25.37.2
```

*Resultado esperado:*

```
84 bytes from 20.25.37.2 icmp_seq=1 ttl=62 time=X ms
84 bytes from 20.25.37.2 icmp_seq=2 ttl=62 time=X ms
84 bytes from 20.25.37.2 icmp_seq=3 ttl=62 time=X ms
```

---

### 5.7 Tabla de comandos de verificación

| Comando | Qué muestra | Equivalente IKEv1 |
|---|---|---|
| `show crypto ikev2 sa` | Estado de la IKEv2 SA. Debe ser `READY`. | `show crypto isakmp sa` (QM_IDLE) |
| `show crypto ikev2 sa detail` | Parámetros negociados, SPIs IKE, identidades locales/remotas. | `show crypto isakmp sa detail` |
| `show crypto ipsec sa` | Child SAs IPSec, selectores de tráfico, contadores de paquetes. | Idéntico en ambas versiones |
| `show crypto ikev2 session` | Sesión activa con estado UP-ACTIVE. | `show crypto engine connections active` |
| `show crypto ikev2 policy` | Confirma la política IKEv2 configurada. | `show crypto isakmp policy` |
| `show crypto map` | Muestra la Crypto Map aplicada y sus parámetros. | Idéntico en ambas versiones |
| `show ip access-lists ACL_IPSEC_TRAFFIC` | Verifica hits en la ACL de tráfico interesante. | Idéntico en ambas versiones |
| `debug crypto ikev2` | Debug del proceso de negociación IKEv2. | `debug crypto isakmp` |

---

## 6. Capturas de Pantalla

A continuación se detalla el índice de evidencias correspondientes a las fases de configuración, verificación y funcionamiento del túnel IPSec IKEv2, alojadas en la carpeta [`screenshots/`](screenshots/README.md):

| # | Archivo de Evidencia | Descripción Técnica Detallada |
|---|---|---|
| 1 | [`01_topologia.png`](screenshots/01_topologia.png) | Topología funcional en PNETLab con nombre completo y matrícula (`20250737`) visibles, todos los dispositivos encendidos. |
| 2 | [`02_ping_sin_vpn.png`](screenshots/02_ping_sin_vpn.png) | Ping desde PC1 (`20.25.37.130`) hacia PC3 (`20.25.37.2`) **antes** de aplicar la configuración IPSec — demuestra conectividad base. |
| 3 | [`03_config_r1_ikev2_proposal.png`](screenshots/03_config_r1_ikev2_proposal.png) | Consola de R1 mostrando la configuración del `crypto ikev2 proposal`, `crypto ikev2 policy` y `crypto ikev2 keyring`. |
| 4 | [`04_config_r1_ikev2_profile.png`](screenshots/04_config_r1_ikev2_profile.png) | Consola de R1 mostrando el `crypto ikev2 profile` con `match identity`, `authentication` y `keyring local`. |
| 5 | [`05_config_r1_cryptomap.png`](screenshots/05_config_r1_cryptomap.png) | Consola de R1 mostrando el Transform Set, la ACL de tráfico interesante y la Crypto Map con `set ikev2-profile` aplicada a `Ethernet0/0`. |
| 6 | [`06_config_r2_completa.png`](screenshots/06_config_r2_completa.png) | Configuración completa de R2 (Site B) mostrando el IKEv2 keyring con peer `192.168.1.10` y la ACL espejo. |
| 7 | [`07_ikev2_sa_ready.png`](screenshots/07_ikev2_sa_ready.png) | Salida de `show crypto ikev2 sa` en R1 mostrando estado `READY` con parámetros AES-256/SHA256/DH14. |
| 8 | [`08_ipsec_sa_contadores.png`](screenshots/08_ipsec_sa_contadores.png) | Salida de `show crypto ipsec sa` mostrando los SPIs de ESP, los selectores de tráfico (`local/remote ident`) y los contadores `#pkts encaps/decaps` incrementando con tráfico activo. |
| 9 | [`09_ping_con_vpn_activa.png`](screenshots/09_ping_con_vpn_activa.png) | Ping exitoso desde PC1 (`20.25.37.130`) hacia PC4 (`20.25.37.3`) con el túnel IPSec IKEv2 activo, TTL=62. |

---

## 7. Consideraciones de Seguridad

### 7.1 Ventajas de seguridad de IKEv2 sobre IKEv1

* **Sin Aggressive Mode inseguro:** IKEv2 no tiene un modo equivalente al Aggressive Mode de IKEv1 que expone el hash de la PSK. Toda la autenticación en IKEv2 viaja cifrada desde el segundo intercambio.
* **PSK asimétrica:** IKEv2 soporta PSKs diferentes para el mensaje local y remoto (`pre-shared-key local` / `pre-shared-key remote`), lo que permite esquemas de autenticación más granulares.
* **Cookie Challenge anti-DoS:** Si el respondedor detecta un volumen alto de solicitudes IKE_SA_INIT, puede emitir cookies que el iniciador debe retornar antes de completar el handshake, protegiendo contra ataques de agotamiento de recursos.
* **Perfect Forward Secrecy nativo:** IKEv2 deriva nuevas claves por cada Child SA usando DH, garantizando que el compromiso de una clave no afecte sesiones pasadas o futuras.

### 7.2 Hardening recomendado

```cisco
! Eliminar la policy ISAKMP por defecto de Cisco (usa DES — inseguro)
no crypto isakmp policy 65535

! Deshabilitar IKEv1 completamente si solo se usa IKEv2
no crypto isakmp enable

! Forzar Perfect Forward Secrecy en Fase 2
crypto map CMAP_SITEA 10 ipsec-isakmp
 set pfs group14

! Restringir el acceso IKE solo al peer conocido en la interfaz WAN
ip access-list extended ACL_WAN_IKEv2
 permit udp host 192.168.1.20 host 192.168.1.10 eq 500
 permit udp host 192.168.1.20 host 192.168.1.10 eq 4500
 permit esp host 192.168.1.20 host 192.168.1.10
 deny ip any any log

interface Ethernet0/0
 ip access-group ACL_WAN_IKEv2 in
```

### 7.3 Diferencia de jerarquía de configuración IKEv1 vs. IKEv2

Una diferencia que genera confusión al migrar de IKEv1 a IKEv2 es la **jerarquía de objetos**. En IKEv1 todo estaba concentrado en un único bloque `crypto isakmp policy`. En IKEv2 está distribuido en cuatro objetos separados con responsabilidades distintas:

| Objeto IKEv2 | Responsabilidad | Equivalente IKEv1 |
|---|---|---|
| `crypto ikev2 proposal` | Algoritmos criptográficos (encr, integ, DH, PRF) | Parte de `crypto isakmp policy` |
| `crypto ikev2 policy` | Selección del proposal según el peer | Parte de `crypto isakmp policy` |
| `crypto ikev2 keyring` | PSK por peer (local y remota) | `crypto isakmp key` |
| `crypto ikev2 profile` | Matching de identidad + autenticación + keyring | No existe en IKEv1 |

La Crypto Map en IKEv2 referencia el profile con `set ikev2-profile` — sin esto, el router intentará negociar con IKEv1 aunque IKEv2 esté configurado.

---

## 8. Video Demostrativo

🎥 **[Ver demostración en YouTube](#)**

**Duración:** máximo 8 minutos

**Contenido del video:**

* ✅ Topología funcional en PNETLab con nombre completo `Jordy Rosario — 20250737` visible.
* ✅ Reloj del sistema operativo visible evidenciando fecha y hora actual.
* ✅ Rostro y voz del autor realizando la explicación técnica del laboratorio.
* ✅ Demostración de los scripts de configuración aplicados en R1 y R2.
* ✅ Verificación de `show crypto ikev2 sa` mostrando estado `READY` con parámetros AES-256/SHA256/DH14.
* ✅ Verificación de `show crypto ikev2 sa detail` mostrando los Traffic Selectors de la Child SA.
* ✅ Verificación de `show crypto ipsec sa` con contadores de paquetes activos.
* ✅ Ping exitoso extremo a extremo entre PC1 (`20.25.37.130`) y PC3/PC4 (`20.25.37.2/3`).

---

## 9. Referencias

* Kaufman, C. et al. (2014). *RFC 7296 — Internet Key Exchange Protocol Version 2 (IKEv2)*. IETF.
* Kent, S. & Seo, K. (2005). *RFC 4301 — Security Architecture for the Internet Protocol*. IETF.
* Eronen, P. & Tschofenig, H. (2007). *RFC 4739 — Multiple Authentication Exchanges in IKEv2*. IETF.
* Cisco Systems. (2024). *Cisco IOS Security Configuration Guide: Secure Connectivity — IKEv2 Configuration*.
* Cisco Systems. (2024). *Cisco IOS Security Command Reference — crypto ikev2*.
* Doraswamy, N. & Harkins, D. (2003). *IPSec: The New Security Standard for the Internet, Intranets, and Virtual Private Networks (2nd Ed.)*. Prentice Hall.
