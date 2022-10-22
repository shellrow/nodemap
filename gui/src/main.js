import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import './index.css';
import VNetworkGraph from "v-network-graph";
import "v-network-graph/lib/style.css";
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import 'element-plus/theme-chalk/dark/css-vars.css';

createApp(App).use(router).use(VNetworkGraph).use(ElementPlus).mount('#app');
