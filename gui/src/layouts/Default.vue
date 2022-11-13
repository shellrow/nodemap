<script setup>
import { ref, onMounted, onUnmounted } from 'vue';
import { MenuIcon, MoonIcon, SunIcon } from '@heroicons/vue/outline';
import { debounce } from 'lodash';
import DropdownMenu from '../components/DropdownMenu.vue';
import Sidebar from '../components/Sidebar.vue';
import { themeChange } from 'theme-change';
import { useRouter } from 'vue-router';

const innerWidth = ref(window.innerWidth);
const show = ref(innerWidth.value >= 1280 ? true : false);
//const theme = ref('light');
const router = useRouter();

const checkWindowSize = () => {
  if (window.innerWidth >= 1280) {
    if (show.value === false && innerWidth.value < 1280) show.value = true;
  } else {
    if (show.value === true) show.value = false;
  }
  innerWidth.value = window.innerWidth;
};

const changeMode = (event) => {
  router.go(router.currentRoute);
};

onMounted(() => {
  window.addEventListener('resize', debounce(checkWindowSize, 100));
  themeChange(false);
});
onUnmounted(() => {
  window.removeEventListener('resize', checkWindowSize);
});
</script>

<template>
<div class="relative">
    <div
      class="
        fixed
        top-0
        w-64
        h-screen
        bg-base-200 
        z-20
        transform
        duration-300
        text-base-content
      "
      :class="{ '-translate-x-full': !show }"
    >
      <Sidebar />
    </div>
    <div
    class="fixed xl:hidden inset-0 bg-gray-900 z-10 opacity-50"
    @click="show = !show"
    v-show="show"
    ></div>
    <div
    class="bg-base-100 h-screen overflow-hidden duration-300"
    :class="{ 'xl:pl-64': show }"
    >
    <div
  class="flex items-center justify-between bg-base-200 rounded shadow m-4 p-4"
>
  <MenuIcon
    class="h-6 w-6 text-base-content cursor-pointer"
    @click="show = !show"
  />
<div class="flex items-center space-x-4">
  <select class="select select-primary" data-choose-theme @change="changeMode">
    <option disabled selected>Select Theme</option>
    <option value="">Default</option>
    <option value="dark">Dark</option>
    <option value="light">Light</option>
    <option value="night">Night</option>
    <option value="dracula">Dracula</option>
    <option value="halloween">Halloween</option>
  </select>
<!--   <MoonIcon
    class="w-7 h-7 text-base-content cursor-pointer"
    @click="changeMode('dark')"
    v-if="theme === 'light'"
  />
  <SunIcon
    class="w-7 h-7 text-base-content cursor-pointer"
    @click="changeMode('light')"
    v-else
  /> -->
  <DropdownMenu />
</div>
</div>
    <div class="text-base-content m-2 p-2">
        <slot />
    </div>
    </div>
</div>
</template>
