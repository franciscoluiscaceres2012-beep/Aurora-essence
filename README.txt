AURORA ESSENCE — primera versión

Requisitos:
- Python 3 (no necesita instalar paquetes).

Cómo abrirla:
1. Abrí una terminal dentro de esta carpeta.
2. Ejecutá: python server.py
3. Entrá desde el navegador a: http://localhost:8000
4. Panel administrador: http://localhost:8000/admin.html
5. La primera vez el sistema te pide crear una contraseña. El usuario es: admin

Funciones incluidas:
- Catálogo público responsive.
- Solo aparecen perfumes con stock mayor a 0.
- Búsqueda y filtro Hombre / Mujer / Unisex.
- Panel privado con login real del lado del servidor.
- Alta, edición y eliminación de perfumes.
- Precio, stock, tamaño, notas, descripción y foto.
- Las fotos se guardan en public/uploads.
- La contraseña se guarda con hash PBKDF2, no en texto plano.

Pendiente para la siguiente etapa:
- Número de WhatsApp y botón de compra/consulta.
- Logo definitivo como archivo vectorial / PNG.
- Dominio y publicación online.
- Opcional: categorías, ofertas, favoritos y analíticas.
