package us.rink.beken

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import us.rink.beken.R.layout.activity_main
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

class MainActivity : AppCompatActivity() {
    private lateinit var editTextName: EditText
    private lateinit var editTextServerName: EditText
    private lateinit var editTextServerPort: EditText
    private lateinit var buttonSend: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        //setContentView(activity_main)
        setContentView(R.layout.activity_main)


        editTextName = findViewById(R.id.editTextName)
        editTextServerName = findViewById(R.id.editTextServerName)
        editTextServerPort = findViewById(R.id.editTextServerPort)
        buttonSend = findViewById(R.id.buttonSend)

        buttonSend.setOnClickListener {
            val userName = editTextName.text.toString()
            val serverName = editTextServerName.text.toString()
            val serverPortStr = editTextServerPort.text.toString()

            if (userName.isNotBlank() && serverName.isNotBlank() && serverPortStr.isNotBlank()) {
                val serverPort = serverPortStr.toInt()
                sendUdpPacket(userName, serverName, serverPort)
            } else {
                Toast.makeText(this, "Please fill in all fields", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun sendUdpPacket(userName: String, serverName: String, serverPort: Int) {
        try {
            val udpSocket = DatagramSocket()
            val serverAddress = InetAddress.getByName(serverName)
            val message = "Hello Android $userName"
            val sendData = message.toByteArray()
            val packet = DatagramPacket(sendData, sendData.size, serverAddress, serverPort)
            udpSocket.send(packet)
            udpSocket.close()
            Toast.makeText(this, "UDP packet sent!", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Error sending UDP packet: ${e.message}", Toast.LENGTH_SHORT).show()
            e.printStackTrace()
        }
    }
}
