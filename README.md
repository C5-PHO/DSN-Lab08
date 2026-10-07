# TechStore · Laboratorio 08

Aplicación local de inventario con control de acceso por rol y tienda, registro, bloqueo de intentos, JWT emitido después de MFA TOTP y acceso con Google/GitHub mediante vinculación de cuentas. Corresponde al caso TechStore del enunciado. No despliega recursos en AWS ni genera cargos de nube.

## Requisitos

- Python 3.11 o superior.
- Una aplicación TOTP como Google Authenticator para iniciar sesión.
- Para probar Google y GitHub, credenciales OAuth creadas por el dueño de las cuentas. No se incluyen en Git.

## Inicio local

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/setup_local.py
.venv/bin/python -m flask --app app:create_app bootstrap-admin
.venv/bin/python -m flask --app app:create_app run --host 127.0.0.1 --port 8088
```

Abre `http://127.0.0.1:8088`. El comando `bootstrap-admin` pide correo, nombre y contraseña sin mostrar la contraseña; solo puede crear el primer administrador. En el primer acceso, escanea el QR TOTP y verifica el código. El archivo `.env` se genera con permisos privados y está excluido de Git. No cambies `TOTP_ENCRYPTION_KEY` mientras quieras conservar los usuarios: cifra sus secretos TOTP.

## Perfiles y permisos

| Perfil | Lectura | Crear/editar precio | Cambiar stock | Eliminar | Reporte | Usuarios |
|---|---|---|---|---|---|---|
| Administrador | Todas las tiendas | Todas | Todas | Todas | Todas | Gestionar |
| Gerente | Su tienda | Su tienda | Su tienda | Su tienda | Su tienda | No |
| Ventas | Su tienda | No | Su tienda | No | No | No |
| Auditor | Todas las tiendas | No | No | No | Todas | No |

El registro público siempre crea un empleado de ventas. El rol enviado por un cliente se ignora; solo un administrador puede cambiarlo. Los cambios de rol o tienda revocan los JWT anteriores. Los precios se almacenan en céntimos enteros para evitar redondeos de coma flotante.

## Autenticación y MFA

1. Registro: correo único, nombre, tienda y contraseña con al menos 8 caracteres, mayúscula, número y símbolo.
2. Login: se valida la contraseña. Cinco fallos bloquean la cuenta 15 minutos.
3. Segundo factor: TOTP de seis dígitos y periodo de 30 segundos. Tres errores bloquean la cuenta 15 minutos. Un código usado no se puede reutilizar.
4. Solo tras MFA se emite un JWT de 30 minutos. El navegador lo recibe en una cookie `HttpOnly` y `SameSite=Lax`; los formularios usan un token CSRF. La API acepta únicamente `Authorization: Bearer <token>`.

La opción TOTP satisface la alternativa A del enunciado; no se implementa el código por email porque se requiere **uno** de esos dos métodos.

## Google y GitHub

El acceso social es opcional hasta que se configuren las aplicaciones OAuth. **No pegues los secretos en GitHub ni en el chat.** Edita solo tu `.env` local:

- Google OAuth Client de tipo web: callback autorizado `http://127.0.0.1:8088/oauth/google/callback`. Completa `GOOGLE_CLIENT_ID` y `GOOGLE_CLIENT_SECRET`.
- GitHub OAuth App: callback `http://127.0.0.1:8088/oauth/github/callback`. Completa `GITHUB_CLIENT_ID` y `GITHUB_CLIENT_SECRET`.

Reinicia la aplicación después de editar `.env`. Primero entra con contraseña y MFA y usa **Vincular Google/GitHub**. Después podrás iniciar sesión con la cuenta vinculada; también se te pedirá TOTP. Una identidad social no vinculada no puede asumir una cuenta por coincidencia de correo.

## API y pruebas

Tras iniciar sesión, `GET /api/token` devuelve un JWT temporal para demostraciones. Trátalo como una contraseña: no lo publiques ni lo muestres en una grabación. Endpoints disponibles:

| Método | Ruta | Uso |
|---|---|---|
| GET | `/api/me` | Perfil autenticado |
| GET, POST | `/api/products` | Listar/crear según rol |
| PATCH, DELETE | `/api/products/<id>` | Actualizar/eliminar según rol y tienda |
| GET | `/api/report` | Resumen para gerente, auditor o administrador |

Ejecuta las pruebas automáticas:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Las pruebas cubren registro sin elevación de privilegios, rechazo de contraseña débil y CSRF, bloqueo por contraseña y MFA, permisos por rol/tienda y revocación de JWT. El flujo real con Google/GitHub requiere las credenciales OAuth y no se considera validado solo porque las rutas estén implementadas.

## Alcance y seguridad

Esta es una aplicación de laboratorio local, no un despliegue de producción. No uses datos reales. Para exponerla a Internet harían falta HTTPS, revisión de seguridad, protección adicional contra abuso, respaldo/recuperación de MFA y operación en un servidor WSGI configurado para producción. La documentación de Flask advierte que su servidor de desarrollo no es adecuado para producción.
