FROM katta/openwrt-rootfs:lede-17.01.4

RUN mkdir -p /var/lock \
  && opkg update \
  && opkg install curl ca-bundle

EXPOSE 80 443 22

CMD ["/sbin/init"]