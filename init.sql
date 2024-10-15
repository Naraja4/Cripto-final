CREATE TABLE Users (
    id_usuario INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    hashed_password CHAR(64) NOT NULL,
    salt CHAR(64) NOT NULL
);
