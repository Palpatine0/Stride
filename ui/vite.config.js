import { defineConfig } from 'vite';
export default defineConfig({server:{proxy:{'/api':'http://127.0.0.1:8092','/sub':'http://127.0.0.1:8092'}}});
