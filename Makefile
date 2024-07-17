USERNAME :=$(shell whoami)
VOLUME := $(sudo docker volume ls -q)

all:
	docker-compose -f docker-compose.yml build --no-cache;
	docker-compose -f docker-compose.yml up -d;

logs:
	docker logs backend
	docker logs database

clean:
	docker container stop database
	docker container stop backend
	docker container stop nginx
	docker network rm transcendance
	# docker volume rm $(VOLUME)

fclean: clean
	docker rm database
	docker rm backend
	docker system prune -af

re: fclean all

.Phony: all logs clean fclean