# OpenWRT package for luadch-ng (DC++ ADC hub server).
#
# Out-of-tree package: drop this directory into an OpenWRT SDK's package/
# tree (or add this repo's openwrt/ as a feed) and `make package/luadch-ng/
# compile` to produce a .apk (25.x SDK) / .ipk (<=24.10 SDK). See
# docs/BUILDING.md (OpenWRT section) for the full recipe. Little-endian
# targets only (adclib Tiger is LE-only); needs OpenWRT >= 22.03 (OpenSSL 3.x).
#
# Layout on the router:
#   /usr/share/luadch-ng   immutable app tree (binary, liblua.so, lib/, core/,
#                          scripts/, lang/); the mutable subdirs are symlinks
#                          into the state dir below.
#   /etc/luadch-ng         writable operator state (cfg/, certs/, log/, data/);
#                          seeded on first start, preserved across upgrades.

include $(TOPDIR)/rules.mk

PKG_NAME:=luadch-ng
# CI overrides PKG_VERSION with the release tag; the default keeps a local
# `make package/luadch-ng/compile` working against a matching source tarball.
PKG_VERSION?=3.2.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# codeload puts the git ref in the URL path (release tags are vX.Y.Z); the
# trailing "?" turns the "/$(PKG_SOURCE)" that the fetcher appends into a query
# string so the ref still resolves to the tag. CI can also pre-stage the
# tarball in dl/ (then the download is skipped entirely).
PKG_SOURCE_URL:=https://codeload.github.com/luadch-ng/luadch-ng/tar.gz/refs/tags/v$(PKG_VERSION)?
# Our own CI-built package from a pinned tag; skip the upstream-style hash pin.
PKG_HASH:=skip

PKG_MAINTAINER:=luadch-ng <https://github.com/luadch-ng/luadch-ng>
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1
CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/luadch-ng
  SECTION:=net
  CATEGORY:=Network
  TITLE:=luadch-ng - DC++ ADC hub server
  URL:=https://github.com/luadch-ng/luadch-ng
  # libopenssl (libcrypto/libssl 3.x) + libstdcpp (the C++ adclib) + zlib
  # (ZLIF stream compression). libatomic: libcrypto needs it on some 32-bit
  # arches (mips); a no-op dependency elsewhere.
  DEPENDS:=+libopenssl +libstdcpp +zlib +libatomic
endef

define Package/luadch-ng/description
  luadch-ng is a DC++ ADC hub server (Lua engine + a thin C launcher). It is
  TLS-only by default and auto-generates its TLS certificate on first boot.
  Operator state (config, registered users, the at-rest master key, logs) lives
  in /etc/luadch-ng and is preserved across package upgrades.
endef

CMAKE_OPTIONS += -DCMAKE_BUILD_TYPE=Release

APPDIR:=/usr/share/luadch-ng
STATEDIR:=/etc/luadch-ng

define Package/luadch-ng/install
	# Immutable app tree: copy the whole CMake-installed prefix, then carve out
	# the mutable subdirs.
	$(INSTALL_DIR) $(1)$(APPDIR)
	$(CP) $(PKG_INSTALL_DIR)/usr/. $(1)$(APPDIR)/
	# Keep the pristine defaults (cfg + shipped plugin data) so first boot can
	# seed /etc/luadch-ng. scripts/ ships a data/ dir of default .tbl files;
	# move it out too, else the symlink below would land INSIDE it.
	$(INSTALL_DIR) $(1)$(APPDIR)/defaults
	mv $(1)$(APPDIR)/cfg          $(1)$(APPDIR)/defaults/cfg
	mv $(1)$(APPDIR)/scripts/data $(1)$(APPDIR)/defaults/data
	# docs/ is not needed on a router - drop it to save flash.
	rm -rf $(1)$(APPDIR)/docs
	# Redirect every writable subdir to the state dir (dangling until the init
	# script seeds it on first start).
	rm -rf $(1)$(APPDIR)/certs $(1)$(APPDIR)/log
	$(LN) $(STATEDIR)/cfg   $(1)$(APPDIR)/cfg
	$(LN) $(STATEDIR)/certs $(1)$(APPDIR)/certs
	$(LN) $(STATEDIR)/log   $(1)$(APPDIR)/log
	$(LN) $(STATEDIR)/data  $(1)$(APPDIR)/scripts/data
	# procd init.
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/luadch-ng.init $(1)/etc/init.d/luadch-ng
endef

$(eval $(call BuildPackage,luadch-ng))
