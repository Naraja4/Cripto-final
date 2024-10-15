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
uvicorn controller:app --host 127.0.0.1 --port 8081 --reload
```

## Para iniciar el frontend:

```
python \src\myproject\manage.py runserver
```


## Librerías:
* MySQL-connector: Proporciona conexión a base de datos MySQL.
* FastAPI: Framework para desarrollo de APIs.
* pycryptodome: Librería de criptografía.
* Django: Framework para desarrollo web.