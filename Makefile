NAME = my_pgp

all:
	cargo build --release
	cp target/release/$(NAME) ./$(NAME)

clean:
	cargo clean

fclean: clean
	rm -f ./$(NAME)

re: fclean all

tests_run:
	cargo test

.PHONY: all clean fclean re tests_run
