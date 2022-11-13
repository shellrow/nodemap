<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { Nodes, Edges, Layouts, defineConfigs} from "v-network-graph";

/* const props = defineProps({
  nodeLabelColor: { type: String, required: false, default: "#ffffff" },
}); */

const nodeLabelColor = ref("#ffffff");
const darkBgThemes = ["","dark", "night", "dracula", "halloween"];

if (darkBgThemes.includes(localStorage.theme.toString())) {
  nodeLabelColor.value = "#ffffff";
} else {
  nodeLabelColor.value = "#000000";
}

const nodes: Nodes = {
  node1: { name: "192.168.1.8" },
  node2: { name: "192.168.1.4" },
  node3: { name: "192.168.1.1" },
  node4: { name: "192.168.1.92" },
  node5: { name: "179.48.249.196" },
  node6: { name: "45.33.32.156" },
  node7: { name: "45.33.34.74" },
  node8: { name: "45.33.34.76" },
  node9: { name: "45.33.35.67" },
  node10: { name: "45.33.40.103" },
}

const edges: Edges = {
  edge1: { source: "node1", target: "node2", label: "1 Gbps" },
  edge2: { source: "node2", target: "node3", label: "1 Gbps" },
  edge3: { source: "node2", target: "node4", label: "1 Gbps" },
  edge4: { source: "node3", target: "node5", label: "1 Gbps" },
  edge5: { source: "node5", target: "node6", label: "1 Gbps" },
  edge6: { source: "node5", target: "node7", label: "1 Gbps" },
  edge7: { source: "node5", target: "node8", label: "1 Gbps" },
  edge8: { source: "node5", target: "node9", label: "1 Gbps" },
  edge9: { source: "node5", target: "node10", label: "1 Gbps" },
}

const configs = reactive(defineConfigs({
  node: {
    selectable: true,
    label: {
      visible: true,
      color: nodeLabelColor.value,
    },
  },
}));

const layouts: Layouts = {
  nodes: {
    node1: { x: 0, y: 80 },
    node2: { x: 200, y: 80 },
    node3: { x: 360, y: 0 },
    node4: { x: 360, y: 160 },
  },
}

onMounted(() => {
  if (darkBgThemes.includes(localStorage.theme.toString())) {
    nodeLabelColor.value = "#ffffff";
  } else {
    nodeLabelColor.value = "#000000";
  }
});

</script>

<template>
  <v-network-graph
    :nodes="nodes"
    :edges="edges"
    :layouts="layouts"
    :configs="configs"
    style="height: 500px;"
  >
  </v-network-graph>

  <div class="overflow-auto">
  <div tabindex="0" class="collapse collapse-open"> 
  <div class="collapse-title text-xl font-medium">
    Latest scan report for 45.33.32.156
  </div>
  <div class="collapse-content"> 
    <table class="table w-full">
    <!-- head -->
    <thead>
      <tr>
        <th>Port No</th>
        <th>Status</th>
        <th>Service Name</th>
        <th>Service Version</th>
      </tr>
    </thead>
    <tbody>
      <!-- row 1 -->
      <tr>
        <td>22</td>
        <th>Open</th>
        <td>SSH</td>
        <td>SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13</td>
      </tr>
      <!-- row 2 -->
      <tr>
        <th>80</th>
        <th>Open</th>
        <td>HTTP</td>
        <td>Server: Apache/2.4.7 (Ubuntu)</td>
      </tr>
    </tbody>
  </table>
  </div>
</div>
  
</div>
</template>
