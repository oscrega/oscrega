create database aceites_tarudo;

use aceites_tarudo;

CREATE TABLE Persona (
    idPersona INT AUTO_INCREMENT PRIMARY KEY,
    tipoPersona BOOLEAN NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    apellido VARCHAR(100) NOT NULL,
    telefono VARCHAR(20),
    email VARCHAR(100),
    direccion VARCHAR(200),
    Asociado BOOLEAN NOT NULL DEFAULT FALSE,
    fechaRegistro DATE NOT NULL,
    estado VARCHAR(20) NOT NULL DEFAULT 'Activo'
);


CREATE TABLE Variedad_Oliva (
    idVariedadOliva INT AUTO_INCREMENT PRIMARY KEY,
    nombreVariedad VARCHAR(50) NOT NULL,
    caracteristicas TEXT,
    perfilSensorial TEXT,
    rendimientoMedio DECIMAL(5,2),
    precioPromedio DECIMAL(10,2),
    estado VARCHAR(20) DEFAULT 'Activo'
);


CREATE TABLE Almacen_Olivas (
    idAlmacen INT AUTO_INCREMENT PRIMARY KEY,
    nombreAlmacen VARCHAR(100) NOT NULL,
    ubicacion VARCHAR(100),
    capacidadTotal DECIMAL(10,2),
    temperaturaOptima DECIMAL(5,2),
    humedadOptima DECIMAL(5,2),
    estado VARCHAR(20) DEFAULT 'Activo'
);


CREATE TABLE Descarga_Olivas (
    idDescarga INT AUTO_INCREMENT PRIMARY KEY,
    idPersona INT NOT NULL,
    idVariedadOliva INT NOT NULL,
    idAlmacen INT NOT NULL,
    kilogramos DECIMAL(10,2) NOT NULL,
    fechaDescarga DATE NOT NULL,
    horaDescarga TIME,
    lote VARCHAR(50),
    temperatura DECIMAL(5,2),
    humedadRelativa DECIMAL(5,2),
    observaciones TEXT,
    FOREIGN KEY (idPersona) REFERENCES Persona(idPersona),
    FOREIGN KEY (idVariedadOliva) REFERENCES Variedad_Oliva(idVariedadOliva),
    FOREIGN KEY (idAlmacen) REFERENCES Almacen_Olivas(idAlmacen)
);


CREATE TABLE Ciclo_Prensado (
    idCicloPrensado INT AUTO_INCREMENT PRIMARY KEY,
    idVariedadOliva INT NOT NULL,
    fechaInicio DATE NOT NULL,
    fechaFin DATE,
    kilogramosUsados DECIMAL(10,2),
    litrosProducidos DECIMAL(10,2),
    rendimiento DECIMAL(5,2),
    presion DECIMAL(10,2),
    temperatura DECIMAL(5,2),
    operario VARCHAR(100),
    observaciones TEXT,
    FOREIGN KEY (idVariedadOliva) REFERENCES Variedad_Oliva(idVariedadOliva)
);


CREATE TABLE Tipo_Aceite (
    idTipoAceite INT AUTO_INCREMENT PRIMARY KEY,
    nombreTipo VARCHAR(50) NOT NULL,
    descripcion TEXT,
    regulacionMinima DECIMAL(5,2),
    acidezMaxima DECIMAL(5,2),
    precioBaseKilo DECIMAL(10,2),
    estado VARCHAR(20) DEFAULT 'Activo'
);


CREATE TABLE Aceite_Basico (
    idAceiteBasico INT AUTO_INCREMENT PRIMARY KEY,
    idTipoAceite INT NOT NULL,
    idVariedadOliva INT NOT NULL,
    idCicloPrensado INT NOT NULL,
    densidad DECIMAL(10,4),
    acidez DECIMAL(5,2),
    polifenoles DECIMAL(5,2),
    fechaElaboracion DATE,
    estado VARCHAR(20) DEFAULT 'Activo',
    puntuacionSensorial DECIMAL(5,2),
    FOREIGN KEY (idTipoAceite) REFERENCES Tipo_Aceite(idTipoAceite),
    FOREIGN KEY (idVariedadOliva) REFERENCES Variedad_Oliva(idVariedadOliva),
    FOREIGN KEY (idCicloPrensado) REFERENCES Ciclo_Prensado(idCicloPrensado)
);


CREATE TABLE Receta_Aceite (
    idReceta INT AUTO_INCREMENT PRIMARY KEY,
    idTipoAceiteElaborado INT NOT NULL,
    nombreReceta VARCHAR(100) NOT NULL,
    descripcion TEXT,
    fechaCreacion DATE NOT NULL,
    estado VARCHAR(20) DEFAULT 'Activa',
    margenBeneficio DECIMAL(5,2),
    notasCatadora TEXT,
    FOREIGN KEY (idTipoAceiteElaborado) REFERENCES Tipo_Aceite(idTipoAceite)
);


CREATE TABLE Composicion_Receta (
    idComposicion INT AUTO_INCREMENT PRIMARY KEY,
    idReceta INT NOT NULL,
    idAceiteBasico INT NOT NULL,
    porcentaje DECIMAL(5,2) NOT NULL,
    litrosPrevistos DECIMAL(10,2),
    notas TEXT,
    FOREIGN KEY (idReceta) REFERENCES Receta_Aceite(idReceta),
    FOREIGN KEY (idAceiteBasico) REFERENCES Aceite_Basico(idAceiteBasico)
);


CREATE TABLE Cuba_Almacen (
    idCuba INT AUTO_INCREMENT PRIMARY KEY,
    idTipoAceite INT NULL,
    idUbicacionCuba INT NOT NULL,
    numeroCuba INT NOT NULL,
    capacidadLitros DECIMAL(10,2) NOT NULL,
    litrosActuales DECIMAL(10,2) DEFAULT 0,
    fechaUltimaLimpieza DATE,
    estado VARCHAR(20) DEFAULT 'Activo',
    material VARCHAR(50),
    temperaturaMantenimiento DECIMAL(5,2),
    FOREIGN KEY (idTipoAceite) REFERENCES Tipo_Aceite(idTipoAceite)
);


CREATE TABLE Produccion_Aceite (
    idProduccion INT AUTO_INCREMENT PRIMARY KEY,
    idReceta INT NOT NULL,
    idCubaProceso INT NOT NULL,
    fechaProduccion DATE NOT NULL,
    litrosProducidos DECIMAL(10,2),
    estado VARCHAR(20) DEFAULT 'Proceso',
    operario VARCHAR(100),
    observaciones TEXT,
    FOREIGN KEY (idReceta) REFERENCES Receta_Aceite(idReceta),
    FOREIGN KEY (idCubaProceso) REFERENCES Cuba_Almacen(idCuba)
);


CREATE TABLE Cliente (
    idCliente INT AUTO_INCREMENT PRIMARY KEY,
    nombreCliente VARCHAR(100) NOT NULL,
    apellidoCliente VARCHAR(100) NOT NULL,
    telefonoCliente VARCHAR(20),
    emailCliente VARCHAR(100),
    tipoCliente VARCHAR(20), -- Mayorista / Bot.
    creditoDisponible DECIMAL(10,2),
    fechaRegistroCliente DATE,
    estadoCliente VARCHAR(20) DEFAULT 'Activo',
    direccionEntrega VARCHAR(200),
    contactoPrincipal VARCHAR(100)
);


CREATE TABLE Venta_Aceite (
    idVenta INT AUTO_INCREMENT PRIMARY KEY,
    idCliente INT NOT NULL,
    idReceta INT NOT NULL,
    idCuba INT NOT NULL,
    fechaVenta DATE NOT NULL,
    litrosVendidos DECIMAL(10,2),
    precioUnitario DECIMAL(10,2),
    totalVenta DECIMAL(10,2),
    estado VARCHAR(20) DEFAULT 'Pendiente',
    numeroAlbaran VARCHAR(50),
    fechaEntrega DATE,
    observaciones TEXT,
    FOREIGN KEY (idCliente) REFERENCES Cliente(idCliente),
    FOREIGN KEY (idReceta) REFERENCES Receta_Aceite(idReceta),
    FOREIGN KEY (idCuba) REFERENCES Cuba_Almacen(idCuba)
);

INSERT INTO Persona (tipoPersona, nombre, apellido, telefono, email, direccion, Asociado, fechaRegistro, estado) VALUES
(true, 'Juan', 'Martín', '600111111', 'juan.martin@mail.es', 'Finca El Olivar', true, '2023-11-01', 'Activo'),
(true, 'Ana', 'Serrano', '600222222', 'ana.serrano@mail.es', 'Camino del Río', false, '2023-11-10', 'Activo'),
(true, 'Pedro', 'López', '600333333', 'pedro.lopez@mail.es', 'Paraje Los Llanos', true, '2023-11-15', 'Activo');

INSERT INTO Variedad_Oliva (nombreVariedad, caracteristicas, perfilSensorial, rendimientoMedio, precioPromedio) VALUES
('Picual', 'Alta estabilidad', 'Intenso y amargo', 23.50, 1.20),
('Hojiblanca', 'Equilibrada', 'Herbáceo', 20.10, 1.30),
('Cornicabra', 'Aromática', 'Frutado medio', 19.80, 1.25),
('Arbequina', 'Suave', 'Dulce y ligero', 18.00, 1.50);

INSERT INTO Almacen_Olivas (nombreAlmacen, ubicacion, capacidadTotal, temperaturaOptima, humedadOptima) VALUES
('Almacén Central', 'Planta Principal', 60000, 15.0, 60.0),
('Almacén Secundario', 'Zona Rural', 40000, 14.5, 65.0);

INSERT INTO Descarga_Olivas (idPersona, idVariedadOliva, idAlmacen, kilogramos, fechaDescarga, horaDescarga, lote) VALUES
(1, 1, 1, 2000, '2024-10-01', '08:00:00', 'PIC-001'),
(2, 2, 1, 1500, '2024-10-01', '09:30:00', 'HOJ-001'),
(3, 3, 2, 1800, '2024-10-02', '10:15:00', 'COR-001'),
(1, 4, 2, 1200, '2024-10-02', '11:00:00', 'ARB-001');

INSERT INTO Ciclo_Prensado (idVariedadOliva, fechaInicio, fechaFin, kilogramosUsados, litrosProducidos, rendimiento, presion, temperatura, operario) VALUES
(1, '2024-10-03', '2024-10-03', 2000, 460, 23.0, 300, 27.0, 'Operario 1'),
(2, '2024-10-04', '2024-10-04', 1500, 300, 20.0, 290, 26.5, 'Operario 2'),
(3, '2024-10-05', '2024-10-05', 1800, 340, 18.9, 295, 26.8, 'Operario 3');

INSERT INTO Tipo_Aceite (nombreTipo, descripcion, acidezMaxima, precioBaseKilo) VALUES
('Virgen Extra', 'Aceite de máxima calidad', 0.8, 4.80),
('Virgen', 'Aceite de calidad media', 2.0, 3.50),
('Aceite Refinado', 'Aceite tratado', 3.5, 2.20),
('Orujo', 'Aceite de subproducto', 5.0, 1.80);

INSERT INTO Aceite_Basico (idTipoAceite, idVariedadOliva, idCicloPrensado, densidad, acidez, polifenoles, fechaElaboracion, puntuacionSensorial) VALUES
(1, 1, 1, 0.9150, 0.3, 450, '2024-10-03', 8.7),
(1, 2, 2, 0.9140, 0.4, 380, '2024-10-04', 8.2),
(2, 3, 3, 0.9160, 1.6, 310, '2024-10-05', 7.5);

INSERT INTO Receta_Aceite (idTipoAceiteElaborado, nombreReceta, descripcion, fechaCreacion, estado, margenBeneficio) VALUES
(1, 'Blend Selección', 'Mezcla premium equilibrada', '2024-10-10', 'Activa', 28.0),
(1, 'Blend Histórico', 'Receta usada en campañas anteriores', '2023-10-10', 'Histórica', 25.0);

INSERT INTO Composicion_Receta (idReceta, idAceiteBasico, porcentaje, litrosPrevistos) VALUES
(1, 1, 60.0, 200),
(1, 2, 40.0, 140),
(2, 3, 100.0, 300);

INSERT INTO Cuba_Almacen (idTipoAceite, idUbicacionCuba, numeroCuba, capacidadLitros, litrosActuales, material) VALUES
(1, 1, 201, 1000, 340, 'Acero Inoxidable'),
(2, 2, 202, 800, 300, 'Acero Inoxidable'),
(NULL, 3, 203, 1200, 0, 'Fibra');

INSERT INTO Produccion_Aceite (idReceta, idCubaProceso, fechaProduccion, litrosProducidos, estado, operario) VALUES
(1, 1, '2024-10-12', 340, 'Completa', 'Operario 1'),
(2, 2, '2023-10-15', 300, 'Completa', 'Operario 2');

INSERT INTO Cliente (nombreCliente, apellidoCliente, telefonoCliente, emailCliente, tipoCliente, creditoDisponible, fechaRegistroCliente) VALUES
('Aceites', 'Gourmet', '955111111', 'ventas@gourmet.es', 'Mayorista', 6000, '2024-01-01'),
('Distribuciones', 'Sur', '955222222', 'contacto@distsur.es', 'Bot.', 2500, '2024-02-01');

INSERT INTO Venta_Aceite (idCliente, idReceta, idCuba, fechaVenta, litrosVendidos, precioUnitario, totalVenta, estado) VALUES
(1, 1, 1, '2024-10-20', 200, 6.80, 1360, 'Completada'),
(2, 2, 2, '2023-10-20', 150, 5.50, 825, 'Completada');





