# Capturas de pantalla — IPSec VPN Basado en Políticas (IKEv2)

Capturas del laboratorio en orden de demostración.

| # | Archivo de Evidencia | Descripción Técnica Detallada |
|---|---|---|
| 1 | [`01_topologia.png`](/screenshots/01_topologia.png) | Topología funcional en PNETLab con nombre completo y matrícula (`20250737`) visibles, todos los dispositivos encendidos. |
| 2 | [`02_ping_sin_vpn.png`](/screenshots/02_ping_sin_vpn.png) | Ping desde PC1 (`20.25.37.130`) hacia PC3 (`20.25.37.2`) **antes** de aplicar la configuración IPSec — demuestra conectividad base. |
| 3 | [`03_config_r1_ikev2_proposal.png`](/screenshots/03_config_r1_ikev2_proposal.png) | Consola de R1 mostrando la configuración del `crypto ikev2 proposal`, `crypto ikev2 policy` y `crypto ikev2 keyring`. |
| 4 | [`04_config_r1_ikev2_profile.png`](/screenshots/04_config_r1_ikev2_profile.png) | Consola de R1 mostrando el `crypto ikev2 profile` con `match identity`, `authentication` y `keyring local`. |
| 5 | [`05_config_r1_cryptomap.png`](/screenshots/05_config_r1_cryptomap.png) | Consola de R1 mostrando el Transform Set, la ACL de tráfico interesante y la Crypto Map con `set ikev2-profile` aplicada a `Ethernet0/0`. |
| 6 | [`06_config_r2_completa.png`](/screenshots/06_config_r2_completa.png) | Configuración completa de R2 (Site B) mostrando el IKEv2 keyring con peer `192.168.1.10` y la ACL espejo. |
| 7 | [`07_ikev2_sa_ready.png`](/screenshots/07_ikev2_sa_ready.png) | Salida de `show crypto ikev2 sa` en R1 mostrando estado `READY` con parámetros AES-256/SHA256/DH14. |
| 8 | [`08_ipsec_sa_contadores.png`](/screenshots/08_ipsec_sa_contadores.png) | Salida de `show crypto ipsec sa` mostrando los SPIs de ESP, los selectores de tráfico (`local/remote ident`) y los contadores `#pkts encaps/decaps` incrementando con tráfico activo. |
| 9 | [`09_ping_con_vpn_activa.png`](/screenshots/09_ping_con_vpn_activa.png) | Ping exitoso desde PC1 (`20.25.37.130`) hacia PC4 (`20.25.37.3`) con el túnel IPSec IKEv2 activo, TTL=62. |
