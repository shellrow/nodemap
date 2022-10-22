<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { Nodes, Edges, Layouts, defineConfigs } from "v-network-graph";

const nodeLabelColor = ref("#ffffff");

if (localStorage.theme === 'dark') {
  nodeLabelColor.value = "#ffffff";
} else {
  nodeLabelColor.value = "#000000";
}

const nodes: Nodes = {
  node1: { name: "192.168.1.8" },
  node2: { name: "192.168.1.4" },
  node3: { name: "192.168.1.1" },
  node4: { name: "192.168.1.92" },
  node5: { name: "192.168.1.112" },
  node6: { name: "192.168.1.156" },
  node7: { name: "192.168.1.128" },
}

const edges: Edges = {
  edge1: { source: "node1", target: "node2", label: "1 Gbps" },
  edge2: { source: "node2", target: "node3", label: "1 Gbps" },
  edge3: { source: "node2", target: "node4", label: "1 Gbps" },
  edge4: { source: "node3", target: "node5", label: "1 Gbps" },
  edge5: { source: "node5", target: "node6", label: "1 Gbps" },
  edge6: { source: "node5", target: "node7", label: "1 Gbps" },
}

const configs = defineConfigs({
  node: {
    selectable: true,
    label: {
      visible: true,
      color: nodeLabelColor.value,
    },
  },
})

const layouts: Layouts = {
  nodes: {
    node1: { x: 0, y: 80 },
    node2: { x: 200, y: 80 },
    node3: { x: 360, y: 0 },
    node4: { x: 360, y: 160 },
  },
}
</script>

<template>
  <v-network-graph
    :nodes="nodes"
    :edges="edges"
    :layouts="layouts"
    :configs="configs"
    style="height: 600px;"
  >
  </v-network-graph>
</template>
