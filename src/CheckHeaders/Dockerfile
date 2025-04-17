FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["src/CheckHeaders/CheckHeaders.csproj", "src/CheckHeaders/"]
RUN dotnet restore "./src/CheckHeaders/CheckHeaders.csproj"
COPY . .

ARG TARGETPLATFORM

RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
    RID=linux-x64 ; \
    elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
    RID=linux-arm64 ; \
    elif [ "$TARGETPLATFORM" = "linux/arm/v7" ]; then \
    RID=linux-arm ; \
    fi \
    && dotnet publish "src/CheckHeaders/CheckHeaders.csproj" -c Release -o /app/publish -r $RID --self-contained false

FROM base AS final
WORKDIR /app
USER $APP_UID

ENTRYPOINT ["./CheckHeaders"]
