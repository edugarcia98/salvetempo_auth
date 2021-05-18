# SalveTempo Auth
Serviço de autenticação do SalveTempo.

## Executando o projeto

- Fazendo o *build* do container:

```shell
docker-compose build --no-cache

cp .env.template .test

docker-compose up
```

- Configurações de banco de dados:

```shell
docker exec -t -i salvetempo_auth_web_1 bash # acessa o container

cd salvetempo_auth/ # acessa o diretório salvetempo_auth

python manage.py migrate # cria os models no banco de dados

python manage.py createsuperuser # cria um superuser para acessar o admin
```

Tendo o projeto configurado, para acesso o *admin* do Django, basta acessar a seguinte URL:
```
http://localhost:8000/admin/
```

> A porta 8000 foi configurada como padrão, caso a mesma já esteja sendo usada, basta alterá-la
> no arquivo `docker-compose.yml`
> **Caso a porta seja alterada, não commitar essa alteração.**

## Testes unitários

Para realizar os testes unitários, basta executar os seguintes comandos dentro do *container*:

```shell
python manage.py test --settings=salvetempo_auth.test_settings # executa todos os testes

python manage.py test [some_path] --settings=salvetempo_auth.test_settings
# executa um ou mais testes unitários específicos
```
