SHELL = /bin/bash
TAG := $(shell echo `git describe --tags`-`git rev-parse --abbrev-ref HEAD` | sed 's/-\([0-9]\)-/-0\1-/; s/-\(HEAD\|master\)$$//')
LAST_TAG := $(shell git describe --tags --abbrev=0)
NEW_TAG := $(shell echo $(LAST_TAG) | perl -lpe 's/v//; $$_ += 0.01; $$_ = sprintf("v%.2f", $$_)')
GO_VERSION := $(shell go version)
GO_LATEST := $(findstring go1.7,$(GO_VERSION))

rclone:
	go install -v ./...

vars:
	@echo SHELL="'$(SHELL)'"
	@echo TAG="'$(TAG)'"
	@echo LAST_TAG="'$(LAST_TAG)'"
	@echo NEW_TAG="'$(NEW_TAG)'"
	@echo GO_VERSION="'$(GO_VERSION)'"
	@echo GO_LATEST="'$(GO_LATEST)'"

# Full suite of integration tests
test:	rclone
	go test ./...
	cd fs && go run test_all.go

# Quick test
quicktest:
	go test ./...
	go test -cpu=2 -race ./...

# Do source code quality checks
check:	rclone
ifdef GO_LATEST
	go vet ./...
	errcheck ./...
	goimports -d . | grep . ; test $$? -eq 1
	golint ./... | grep -E -v '(StorageUrl|CdnUrl)' ; test $$? -eq 1
else
	@echo Skipping tests as not on Go stable
endif

# Get the build dependencies
build_dep:
	go get -t ./...
ifdef GO_LATEST
	go get -u github.com/kisielk/errcheck
	go get -u golang.org/x/tools/cmd/goimports
	go get -u github.com/golang/lint/golint
	go get -u github.com/mitchellh/gox
	go get -u github.com/inconshreveable/mousetrap
endif

# Update dependencies
update:
	go get -t -u -f -v ./...

doc:	rclone.1 MANUAL.html MANUAL.txt

rclone.1:	MANUAL.md
	pandoc -s --from markdown --to man MANUAL.md -o rclone.1

MANUAL.md:	bin/make_manual.py docs/content/*.md commanddocs
	./bin/make_manual.py

MANUAL.html:	MANUAL.md
	pandoc -s --from markdown --to html MANUAL.md -o MANUAL.html

MANUAL.txt:	MANUAL.md
	pandoc -s --from markdown --to plain MANUAL.md -o MANUAL.txt

commanddocs: rclone
	rclone gendocs docs/content/commands/

install: rclone
	install -d ${DESTDIR}/usr/bin
	install -t ${DESTDIR}/usr/bin ${GOPATH}/bin/rclone

clean:
	go clean ./...
	find . -name \*~ | xargs -r rm -f
	rm -rf build docs/public
	rm -f rclone rclonetest/rclonetest

website:
	cd docs && hugo

upload_website:	website
	rclone -v sync docs/public memstore:www-rclone-org

upload:
	rclone -v copy build/ memstore:downloads-rclone-org

upload_github:
	./bin/upload-github $(TAG)

cross:	doc
	./bin/cross-compile $(TAG)

beta:
	./bin/cross-compile $(TAG)β
	rm build/*-current-*
	rclone -v copy build/ memstore:pub-rclone-org/$(TAG)β
	@echo Beta release ready at http://pub.rclone.org/$(TAG)%CE%B2/

travis_beta:
	./bin/cross-compile $(TAG)β
	rm build/*-current-*
	rclone --config bin/travis.rclone.conf -v copy build/ memstore:beta-rclone-org/$(TAG)
	@echo Beta release ready at http://beta.rclone.org/$(TAG)/

serve:	website
	cd docs && hugo server -v -w

tag:	doc
	@echo "Old tag is $(LAST_TAG)"
	@echo "New tag is $(NEW_TAG)"
	echo -e "package fs\n\n// Version of rclone\nvar Version = \"$(NEW_TAG)-DEV\"\n" | gofmt > fs/version.go
	perl -lpe 's/VERSION/${NEW_TAG}/g; s/DATE/'`date -I`'/g;' docs/content/downloads.md.in > docs/content/downloads.md
	git tag $(NEW_TAG)
	@echo "Add this to changelog in docs/content/changelog.md"
	@echo "  * $(NEW_TAG) -" `date -I`
	@git log $(LAST_TAG)..$(NEW_TAG) --oneline
	@echo "Then commit the changes"
	@echo git commit -m \"Version $(NEW_TAG)\" -a -v
	@echo "And finally run make retag before make cross etc"

retag:
	git tag -f $(LAST_TAG)

gen_tests:
	cd fstest/fstests && go generate
