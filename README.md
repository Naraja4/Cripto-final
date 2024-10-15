# Proyecto Criptografía

## Integrantes -  Grupo 16

* Guillermo Candela Gabaldón - 100548480
* Iván Fernández Martín-Gil - 100472263
* Ismael Zhu Zhou - 100472215

## Para iniciar la base de datos:

```
docker-compose up -d
```

## Para iniciar el controlador:

```
uvicorn controller:app --host 0.0.0.0 --port 8081 --reload
```

## Librerías:
* MySQL-connector: Proporciona conexión a base de datos MySQL.
* FastAPI: Framework para desarrollo de APIs.
* pycryptodome: Librería de criptografía.