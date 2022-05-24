docker run --rm -it --entrypoint /bin/ash --name="pethublocal" -p 80:80 -p 443:443 -v $PWD/run:/code/run pethublocal
