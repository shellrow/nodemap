import { createRouter, createWebHistory } from 'vue-router';
import Dashboard from '../pages/Dashboard.vue';
import Profile from '../pages/Profile.vue';
import Log from '../pages/Log.vue';
import Status from '../pages/Status.vue';

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard,
  },
  {
    path: '/profile',
    name: 'Profile',
    component: Profile,
  },
  {
    path: '/log',
    name: 'Log',
    component: Log,
  },
  {
    path: '/status',
    name: 'Status',
    component: Status,
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;
