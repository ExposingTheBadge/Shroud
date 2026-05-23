package com.ghostlink.client

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MessagesScreen(vm: GhostlinkVM) {
    var messageText by remember { mutableStateOf("") }
    var recipientID by remember { mutableStateOf("") }
    var showRecipientDialog by remember { mutableStateOf(false) }
    var showContactsSheet by remember { mutableStateOf(false) }
    var showGroupsSheet by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("GHOSTLINK") },
                actions = {
                    Text(
                        vm.deviceID.take(12) + "...",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    IconButton(onClick = { showGroupsSheet = true }) {
                        Text("👥", fontSize = 18.sp)
                    }
                    IconButton(onClick = { showContactsSheet = true }) {
                        Text("➕", fontSize = 18.sp)
                    }
                }
            )
        },
        bottomBar = {
            Surface(tonalElevation = 3.dp) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = messageText,
                        onValueChange = { messageText = it },
                        placeholder = { Text("E2E Encrypted Message") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    Spacer(Modifier.width(8.dp))
                    IconButton(
                        onClick = {
                            if (recipientID.isEmpty()) {
                                showRecipientDialog = true
                            } else {
                                vm.sendMessage(recipientID, messageText)
                                messageText = ""
                            }
                        },
                        enabled = messageText.isNotEmpty()
                    ) {
                        Text("📤", fontSize = 22.sp)
                    }
                }
            }
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            items(vm.messages) { msg ->
                val isMine = msg.senderDeviceID == vm.deviceID
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = if (isMine) Arrangement.End else Arrangement.Start
                ) {
                    Surface(
                        color = if (isMine) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.surfaceVariant,
                        shape = MaterialTheme.shapes.medium,
                        modifier = Modifier.widthIn(max = 280.dp)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                msg.decryptedBody ?: "[Encrypted]",
                                color = if (isMine) MaterialTheme.colorScheme.onPrimary
                                else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                msg.senderDeviceID.take(8) + "...",
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                color = if (isMine) MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.5f)
                                else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            )
                        }
                    }
                }
            }
        }
    }

    // Recipient dialog
    if (showRecipientDialog) {
        AlertDialog(
            onDismissRequest = { showRecipientDialog = false },
            title = { Text("Recipient Device ID") },
            text = {
                OutlinedTextField(
                    value = recipientID,
                    onValueChange = { recipientID = it },
                    label = { Text("Device ID") },
                    singleLine = true
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showRecipientDialog = false
                    vm.sendMessage(recipientID, messageText)
                    messageText = ""
                }) { Text("Send") }
            },
            dismissButton = { TextButton(onClick = { showRecipientDialog = false }) { Text("Cancel") } }
        )
    }
}
