FROM microsoft/aspnet

COPY omco.erp.web /app

COPY NuGet.Config /root/.config/NuGet/NuGet.Config

WORKDIR /app

run ["dnu","restore"]

ENTRYPOINT ["dnx",".","kestrel"]
