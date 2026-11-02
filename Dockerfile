FROM node:22-bookworm-slim AS ui
WORKDIR /build
COPY ui/package*.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --uid 10001 --create-home console
COPY api/ ./api/
COPY --from=ui /build/dist ./ui/dist/
RUN mkdir /data && chown console:console /data
USER console
EXPOSE 8092
CMD ["python", "-m", "api.server"]
