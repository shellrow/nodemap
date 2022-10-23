<script setup>
import { ref, onMounted, onUnmounted } from 'vue';
import { FingerPrintIcon, CogIcon} from '@heroicons/vue/outline';

const show = ref(false);
const root = ref(null);

const toggle = () => {
  show.value = !show.value;
};

const clickOutside = (e) => {
  if (!root.value.contains(e.target) && show.value) {
    show.value = false;
  }
};

onMounted(() => document.addEventListener('click', clickOutside));
onUnmounted(() => document.removeEventListener('click', clickOutside));

</script>

<template>
    <div class="relative" ref="root">
        <img src="../assets/vue.svg" class="rounded-full w-10 h-10 cursor-pointer" @click="toggle"/>
        <transition enter-active-class="transition duration-300" enter-from-class="transform opacity-0 -translate-y-2 " leave-active-class="transition duration-300" leave-to-class="transform opacity-0 -translate-y-2">
        <div class="absolute top-16 right-0 z-10 w-40 py-2 bg-base-200 rounded-sm shadow" v-show="show">
            <ul>
                <li class="text-base-content hover:bg-base-100 hover:text-base-content p-2">
                <router-link to="/profile" class="flex items-center space-x-2">
                    <FingerPrintIcon class="w-5 h-5" />
                    <span class="text-sm font-bold">System Info</span>
                </router-link>
                </li>
                <li class="text-base-content hover:bg-base-100 hover:text-base-content p-2">
                    <a href="/#" class="flex items-center space-x-2">
                        <CogIcon class="w-5 h-5" />
                        <span class="text-sm font-bold">Setting</span>
                    </a>
                </li>
            </ul>
        </div>
        </transition>
    </div>
</template>
