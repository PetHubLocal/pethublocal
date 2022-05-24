FROM python:3.9-alpine

EXPOSE 80 443

WORKDIR /code

# RUN apk add --no-cache gcc musl-dev linux-headers

COPY . .

RUN pip install .

WORKDIR /code/run

ENTRYPOINT ["pethublocal", "start"]
