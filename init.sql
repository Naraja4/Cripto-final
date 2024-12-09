CREATE TABLE Users (
    id_usuario INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    hashed_password CHAR(64) NOT NULL,
    salt CHAR(64) NOT NULL
);

CREATE TABLE Productos (
    id_post INT AUTO_INCREMENT PRIMARY KEY,
    id_usuario INT NOT NULL,
    descripcion TEXT NOT NULL,
    precio VARCHAR(256) NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_usuario) REFERENCES Users(id_usuario)
);

CREATE TABLE Chat (
    id_chat INT AUTO_INCREMENT PRIMARY KEY,
    id_usuario INT NOT NULL,
    id_usuario2 INT NOT NULL,
    FOREIGN KEY (id_usuario) REFERENCES Users(id_usuario),
    FOREIGN KEY (id_usuario2) REFERENCES Users(id_usuario)
);

CREATE TABLE Mensajes (
    id_mensaje INT AUTO_INCREMENT PRIMARY KEY,
    id_chat INT NOT NULL,
    id_emisor INT NOT NULL,
    id_receptor INT NOT NULL,
    mensaje_encriptado_receptor TEXT NOT NULL,
    mensaje_encriptado_emisor TEXT NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_chat) REFERENCES Chat(id_chat),
    FOREIGN KEY (id_emisor) REFERENCES Users(id_usuario),
    FOREIGN KEY (id_receptor) REFERENCES Users(id_usuario)
);
