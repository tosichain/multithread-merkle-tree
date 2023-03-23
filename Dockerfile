FROM rust:1.68.0 as build

WORKDIR /merkle-tree-hash

COPY . .

RUN cargo build --release

RUN cargo install --path . --root /opt/tosi/bin

COPY test-merkle-tree-hash /opt/tosi/share/examples/

CMD ["/opt/tosi/bin/bin/merkle-tree-hash", "--input", "/opt/tosi/share/examples/test-merkle-tree-hash", "--log2-word-size", "3", "--log2_leaf_size", "12", "--log2_root_size", "30"]

RUN rm -rf /merkle-tree-hash