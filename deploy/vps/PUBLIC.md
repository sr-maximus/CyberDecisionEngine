# Acceso público protegido

Este perfil añade acceso desde cualquier navegador con HTTPS, usuario y
contraseña. Es un espacio de trabajo compartido para personas autorizadas;
no separa datos entre clientes. Aplicar las tres composiciones en orden:
`compose.yml`, `operator.yml`, `public.yml`. El perfil privado anterior conserva
su funcionamiento independiente.

## Identidad y permisos

`CDE_AUTH_ENABLED=true` exige configuración válida de cuentas en el servidor.
La API valida la sesión y el rol en todas sus rutas protegidas e informes;
modificar localStorage o cabeceras de rol no concede permisos. Las contraseñas
usan PBKDF2-SHA256 con 600000 iteraciones y sal individual. Las sesiones tienen
token aleatorio, cookie Secure/HttpOnly/SameSite=Strict, revocación al salir,
inactividad máxima de 30 minutos y duración absoluta de 8 horas.

- `superadmin`: administración y operación del espacio compartido.
- `operador` (rol interno `analyst`): consulta y operación autorizada de análisis,
  evidencias e informes; sin administración, licencias ni eliminación de datos.

El middleware exige origen HTTPS exacto y token CSRF para modificar estado.
Los intentos de acceso se limitan en Nginx y en un registro persistente del
servidor. Las vistas HTML de informes llevan sandbox estricto: conservan su
contenido estático, pero no ejecutan scripts o controles interactivos del HTML.
El panel principal de la aplicación conserva su JavaScript normal.

No hay MFA/SSO en este perfil. Las cuentas y sus contraseñas se gestionan en
la configuración privada del servidor; los controles locales de usuarios de
la versión de laboratorio no se ofrecen como administración pública.

## Preparación

1. Apuntar un nombre DNS controlado al VPS. Si existe AAAA, también debe apuntar
   al IPv6 correcto. Instalar Caddy del repositorio oficial como servicio del host.
2. Generar las cuentas fuera del repositorio:

```sh
sudo python3 scripts/vps_public_users.py --output-dir /etc/cde/secrets \
  --superadmin-credentials /etc/cde/secrets/operator-credentials.json
sudo chmod 444 /etc/cde/secrets/auth_users.json
```

El directorio padre debe conservar permisos 700. `auth_users.json` contiene
solo hashes y se monta en API; `public-credentials.json` contiene contraseñas y
se entrega exclusivamente por canal privado. No montar este último en API/web.

3. Configurar estas variables además de las del perfil privado:

```sh
export CDE_PUBLIC_ORIGIN=https://app.example.com
export CDE_PROXY_SUBNET="$(sudo docker network inspect cde-vps_application --format '{{(index .IPAM.Config 0).Subnet}}')"
```

La subred indicada debe ser exclusivamente la red de aplicación aislada donde
Nginx contacta a la API. Uvicorn solo confía en las cabeceras reenviadas desde
esa subred; Caddy sobrescribe la IP recibida del cliente y Nginx la conserva.
Nunca publicar la API ni confiar en cabeceras IP de todos los orígenes.

4. Construir y levantar el código revisado con los tres archivos Compose.
   Verificar el login, roles, CSRF y rechazo anónimo antes de habilitar el proxy
   público. Adaptar `Caddyfile.example` al nombre DNS verificado. Caddy conecta
   a `127.0.0.1:18080`; la aplicación conserva todos sus puertos en redes privadas.
5. Abrir TCP 80 para validación del certificado y redirección, TCP 443 para HTTPS
   y conservar SSH con llave para administración. Aplicar el firewall del host
   y del proveedor en IPv4/IPv6. Las personas que usan la aplicación no necesitan SSH.
6. Ejecutar `install-operations.sh` con `CDE_RELEASE`, `CDE_PUBLIC_ORIGIN` y
   `CDE_PROXY_SUBNET` exportados. Las copias incluyen la base, los volúmenes,
   sesiones, configuración privada y configuración de Caddy, cifrados con restic.

## Importación autorizada de una corrida

Transferir solo registros y archivos de la corrida seleccionada a los volúmenes
y a PostgreSQL mediante un procedimiento privado, transaccional y con checksums.
No copiar la base completa del equipo, usuarios/configuraciones locales ni
recolecciones al checkout Git. Mantener una copia previa, pausar API durante
la importación y verificar historial, contexto e informes al reiniciar.

## Verificación y límites

Comprobar HTTPS válido y redirección, ambos logins, rechazo de contraseñas
incorrectas, bloqueo de administración al operador, CSRF, revocación al salir,
ausencia de acceso anónimo a corridas/informes y recuperación tras reiniciar
contenedores. Repetir backup/restauración con archivos privados modo 600.

Un VPS sigue siendo un punto único de fallo. Las copias locales necesitan una
réplica externa independiente y alertas fuera del servidor para continuidad.
Las integraciones opcionales y la IA requieren sus servicios/credenciales;
el acceso público no las habilita automáticamente.

Fuentes: [Caddy y HTTPS automático](https://caddyserver.com/docs/automatic-https),
[Instalación oficial de Caddy](https://caddyserver.com/docs/install).
