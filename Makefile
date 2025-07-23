clean:
	rm -rf *.tar.gz dist build *.egg-info *.rpm
	find . -name "*.pyc" | xargs rm
	find . -name "__pycache__" | xargs rm -rf

test:
	@source .venv/bin/activate && python -m pytest ldap_faker/test/ -v

dist: clean
	@python -m build

release: dist
	@bin/release.sh

compile: uv.lock
	@uv pip compile --group docs --group test pyproject.toml -o requirements.txt

tox:
	# create a tox pyenv virtualenv based on 3.7.x
	# install tox and tox-pyenv in that ve
	# activate that ve before running this
	@tox
