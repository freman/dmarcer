.PHONY: build assets clean

BINARY=dmarcer
GEOIP_DB=assets/dbip-country-lite.mmdb
GEOIP_URL=https://download.db-ip.com/free/dbip-country-lite-$(shell date +%Y-%m).mmdb.gz

build: $(GEOIP_DB)
	go build -o $(BINARY) ./cmd/dmarcer

assets: $(GEOIP_DB)

$(GEOIP_DB):
	@echo "Downloading DB-IP Country Lite database..."
	@mkdir -p assets
	@curl -fL "$(GEOIP_URL)" | gunzip -c > $@ || \
		(echo "Failed to download GeoIP DB. Build will continue without it (no country data)."; touch $@)

clean:
	rm -f $(BINARY) $(GEOIP_DB)
