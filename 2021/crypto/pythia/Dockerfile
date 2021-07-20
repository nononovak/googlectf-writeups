FROM sagemath/sagemath:latest

USER sage
RUN /home/sage/sage/local/bin/pip3 install --upgrade pip
RUN /home/sage/sage/local/bin/python3 -m pip install --upgrade pip
RUN /home/sage/sage/local/bin/pip3 install cryptography pycryptodome bitstring
WORKDIR /work
ADD --chown=sage https://raw.githubusercontent.com/julialen/key_multicollision/main/collide_gcm.sage .
RUN sed -i s/use_magma=True/use_magma=False/ collide_gcm.sage
RUN sage collide_gcm.sage 1
RUN mv collide_gcm.sage.py collide_gcm_sage.py
COPY solve.py .
COPY partitions.txt .

CMD ./solve.py
