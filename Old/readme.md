# Crete docker container

docker run -it --rm --privileged -e DISPLAY \
             -v /tmp/.X11-unix:/tmp/.X11-unix \
             -v /lib/modules:/lib/modules \
             mn_ryu_sdn


docker build -t mn_ryu_sdn . 
