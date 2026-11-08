# Frontend: HTML/CSS/JS estáticos servidos por nginx sin privilegios, que además reenvía /api/ al backend
# (mismo origen: la cookie de sesión SameSite=Strict funciona y no hace falta CORS).
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY public/ /usr/share/nginx/html/
EXPOSE 8080
