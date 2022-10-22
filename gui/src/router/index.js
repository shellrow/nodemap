import { createRouter, createWebHistory } from 'vue-router';
import Dashboard from '../pages/Dashboard.vue';
import Profile from '../pages/Profile.vue';
import PortScan from '../pages/PortScan.vue';
import HostScan from '../pages/HostScan.vue';
import Ping from '../pages/Ping.vue';
import Traceroute from '../pages/Traceroute.vue';
import Log from '../pages/Log.vue';
import Network from '../pages/Network.vue';

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Network,
  },
  {
    path: '/profile',
    name: 'Profile',
    component: Profile,
  },
  {
    path: '/port',
    name: 'PortScan',
    component: PortScan,
  },
  {
    path: '/host',
    name: 'HostScan',
    component: HostScan,
  },
  {
    path: '/ping',
    name: 'Ping',
    component: Ping,
  },
  {
    path: '/trace',
    name: 'Traceroute',
    component: Traceroute,
  },
  {
    path: '/log',
    name: 'Log',
    component: Log,
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;
