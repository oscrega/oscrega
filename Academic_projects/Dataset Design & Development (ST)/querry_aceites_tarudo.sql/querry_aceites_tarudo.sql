# VISTAS

# 1. Vista de descargas por agricultor
CREATE VIEW vw_descargas_por_agricultor AS
SELECT Persona.idPersona, Persona.nombre, Persona.apellido, Persona.Asociado, Variedad_Oliva.nombreVariedad, Descarga_Olivas.kilogramos, Descarga_Olivas.fechaDescarga, Almacen_Olivas.nombreAlmacen
FROM Descarga_Olivas
JOIN Persona ON Descarga_Olivas.idPersona = Persona.idPersona
JOIN Variedad_Oliva ON Descarga_Olivas.idVariedadOliva = Variedad_Oliva.idVariedadOliva
JOIN Almacen_Olivas ON Descarga_Olivas.idAlmacen = Almacen_Olivas.idAlmacen;


# 2. Vista de inventario de olivas por variedad
CREATE VIEW vw_inventario_olivas_por_variedad AS
SELECT Variedad_Oliva.nombreVariedad, SUM(Descarga_Olivas.kilogramos) AS totalKilogramos
FROM Descarga_Olivas
JOIN Variedad_Oliva ON Descarga_Olivas.idVariedadOliva = Variedad_Oliva.idVariedadOliva
GROUP BY Variedad_Oliva.nombreVariedad;


# 3. Vista de recetas con su composición
CREATE VIEW vw_recetas_composicion AS
SELECT Receta_Aceite.idReceta, Receta_Aceite.nombreReceta, Aceite_Basico.idAceiteBasico, Composicion_Receta.porcentaje
FROM Receta_Aceite
JOIN Composicion_Receta ON Receta_Aceite.idReceta = Composicion_Receta.idReceta
JOIN Aceite_Basico ON Composicion_Receta.idAceiteBasico = Aceite_Basico.idAceiteBasico;


# 4. Vista de ventas detalladas
CREATE VIEW vw_ventas_detalladas AS
SELECT Venta_Aceite.idVenta, Cliente.nombreCliente, Cliente.apellidoCliente, Receta_Aceite.nombreReceta, Venta_Aceite.litrosVendidos, Venta_Aceite.totalVenta, Venta_Aceite.fechaVenta
FROM Venta_Aceite
JOIN Cliente ON Venta_Aceite.idCliente = Cliente.idCliente
JOIN Receta_Aceite ON Venta_Aceite.idReceta = Receta_Aceite.idReceta;

# PRUEBAS UNITARIAS

# 1. una cuba solo contiene un tipo de aceite
SELECT idCuba
FROM Cuba_Almacen
WHERE idTipoAceite IS NOT NULL
GROUP BY idCuba
HAVING COUNT(DISTINCT idTipoAceite) > 1;


# 2. proporciones de receta = 100 %
SELECT
    idReceta,
    SUM(porcentaje) AS total_porcentaje
FROM Composicion_Receta
GROUP BY idReceta
HAVING total_porcentaje <> 100;


# 3. litros actuales no superan la capacidad
SELECT idCuba
FROM Cuba_Almacen
WHERE litrosActuales > capacidadLitros;


# 4. inventarios nunca negativos
SELECT *
FROM Cuba_Almacen
WHERE litrosActuales < 0;


# 5. agricultores asociados y no asociados
SELECT
    Asociado,
    COUNT(*) AS total_agricultores
FROM Persona
GROUP BY Asociado;

# CONSULTAS BÁSICAS

# 1. Listar todos los agricultores
SELECT idPersona, nombre, apellido, Asociado
FROM Persona;


# 2. Mostrar todas las variedades de oliva
SELECT nombreVariedad
FROM Variedad_Oliva;


# 3. Ver todas las recetas activas
SELECT nombreReceta, fechaCreacion, estado
FROM Receta_Aceite
WHERE estado = 'Activa';


# 4. Mostrar todas las cubas y su capacidad
SELECT idCuba, idTipoAceite, idUbicacionCuba, numeroCuba, capacidadLitros, litrosActuales, estado
FROM Cuba_Almacen;


# 5. Listar clientes registrados
SELECT idCliente, nombreCliente, apellidoCliente, tipoCliente, estadoCliente
FROM Cliente;

# CONSULTAS COMPLEJAS

# 1. Total de kilos descargados por agricultor
SELECT Persona.idPersona, Persona.nombre, Persona.apellido, SUM(Descarga_Olivas.kilogramos) AS totalKilogramos
FROM Descarga_Olivas
JOIN Persona ON Descarga_Olivas.idPersona = Persona.idPersona
GROUP BY Persona.idPersona, Persona.nombre, Persona.apellido;


# 2. Producción total de aceite por variedad
SELECT Variedad_Oliva.idVariedadOliva, Variedad_Oliva.nombreVariedad, SUM(Ciclo_Prensado.litrosProducidos) AS litrosTotales
FROM Ciclo_Prensado
JOIN Variedad_Oliva ON Ciclo_Prensado.idVariedadOliva = Variedad_Oliva.idVariedadOliva
GROUP BY Variedad_Oliva.idVariedadOliva, Variedad_Oliva.nombreVariedad;


# 3. Ventas totales por cliente
SELECT Cliente.idCliente, Cliente.nombreCliente, Cliente.apellidoCliente, SUM(Venta_Aceite.totalVenta) AS facturacionTotal
FROM Venta_Aceite
JOIN Cliente ON Venta_Aceite.idCliente = Cliente.idCliente
GROUP BY Cliente.idCliente, Cliente.nombreCliente, Cliente.apellidoCliente;


# 4. Recetas históricas que han tenido ventas
SELECT DISTINCT Receta_Aceite.idReceta, Receta_Aceite.nombreReceta, Receta_Aceite.estado
FROM Receta_Aceite
JOIN Venta_Aceite ON Receta_Aceite.idReceta = Venta_Aceite.idReceta
WHERE Receta_Aceite.estado = 'Histórica';


# 5. Inventario disponible por cuba y tipo de aceite
SELECT Cuba_Almacen.idCuba, Cuba_Almacen.numeroCuba, Cuba_Almacen.idTipoAceite, Tipo_Aceite.nombreTipo, Cuba_Almacen.litrosActuales
FROM Cuba_Almacen
LEFT JOIN Tipo_Aceite ON Cuba_Almacen.idTipoAceite = Tipo_Aceite.idTipoAceite;


# 6. Clientes que han comprado más de 100 litros en total
SELECT Cliente.idCliente, Cliente.nombreCliente, Cliente.apellidoCliente, SUM(Venta_Aceite.litrosVendidos) AS litrosComprados
FROM Venta_Aceite
JOIN Cliente ON Venta_Aceite.idCliente = Cliente.idCliente
GROUP BY Cliente.idCliente, Cliente.nombreCliente, Cliente.apellidoCliente
HAVING litrosComprados > 100;

