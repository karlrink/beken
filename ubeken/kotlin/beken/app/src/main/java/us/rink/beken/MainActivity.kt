package us.rink.beken

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import us.rink.beken.R.layout.activity_main
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

import android.content.SharedPreferences

import android.preference.PreferenceManager
import android.text.Editable
import android.text.TextWatcher
import android.widget.TextView

class MainActivity : AppCompatActivity() {

    private lateinit var editTextKey: EditText
    private lateinit var editTextName: EditText
    private lateinit var editTextServerName: EditText
    private lateinit var editTextServerPort: EditText
    private lateinit var buttonSend: Button

    private lateinit var textViewResponse: TextView


    private lateinit var sharedPreferences: SharedPreferences



    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)



        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this)

        textViewResponse = findViewById(R.id.textViewResponse)

        textViewResponse.text = "None"



        editTextKey = findViewById(R.id.editTextKey)
        editTextName = findViewById(R.id.editTextName)
        editTextServerName = findViewById(R.id.editTextServerName)
        editTextServerPort = findViewById(R.id.editTextServerPort)
        buttonSend = findViewById(R.id.buttonSend)

        // Load the saved values from SharedPreferences
        editTextKey.setText(sharedPreferences.getString("key", ""))
        editTextName.setText(sharedPreferences.getString("name", ""))
        editTextServerName.setText(sharedPreferences.getString("serverName", ""))
        editTextServerPort.setText(sharedPreferences.getString("serverPort", ""))

        // Add TextWatchers to EditText fields to save input as it changes
        editTextKey.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                sharedPreferences.edit().putString("key", s.toString()).apply()
            }

            override fun afterTextChanged(s: Editable?) {}
        })

        editTextName.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                sharedPreferences.edit().putString("name", s.toString()).apply()
            }

            override fun afterTextChanged(s: Editable?) {}
        })

        editTextServerName.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                sharedPreferences.edit().putString("serverName", s.toString()).apply()
            }

            override fun afterTextChanged(s: Editable?) {}
        })

        editTextServerPort.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                sharedPreferences.edit().putString("serverPort", s.toString()).apply()
            }

            override fun afterTextChanged(s: Editable?) {}
        })

        buttonSend.setOnClickListener {

            val userKey = editTextKey.text.toString()
            val userName = editTextName.text.toString()
            val serverName = editTextServerName.text.toString()
            val serverPortStr = editTextServerPort.text.toString()

            if (userName.isNotBlank() && serverName.isNotBlank() && serverPortStr.isNotBlank() && userKey.isNotBlank()) {
                val serverPort = serverPortStr.toInt()
                sendUdpPacket(userName, userKey, serverName, serverPort)
            } else {
                Toast.makeText(this, "Please fill in all fields", Toast.LENGTH_SHORT).show()
            }
        }
    }



    private fun sendUdpPacket(userName: String, userKey: String, serverName: String, serverPort: Int) {
        // Use a coroutine to perform the network operation on a background thread
        GlobalScope.launch(Dispatchers.IO) {
            try {
                val udpSocket = DatagramSocket()
                val serverAddress = InetAddress.getByName(serverName)
                val message = "Hello Android $userName $userKey"
                val sendData = message.toByteArray()
                val packet = DatagramPacket(sendData, sendData.size, serverAddress, serverPort)
                udpSocket.send(packet)

                // Display "UDP packet sent!" on the main thread
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "UDP packet sent!", Toast.LENGTH_SHORT).show()
                }

                // Receive the response from the server
                val receiveData = ByteArray(1024)
                val receivePacket = DatagramPacket(receiveData, receiveData.size)
                udpSocket.receive(receivePacket)
                val serverResponse = String(receivePacket.data, 0, receivePacket.length)

                // Close the socket
                udpSocket.close()

                // Update the UI on the main thread
                withContext(Dispatchers.Main) {
                    if (serverResponse.isNotEmpty()) {
                        // Display the server response in the TextView
                        textViewResponse.text = "Server Response: $serverResponse"
                    } else {
                        // Display "No response" in the TextView if the server response is empty
                        textViewResponse.text = "No response"
                    }
                }
            } catch (e: Exception) {
                // Handle any exceptions here
                e.printStackTrace()

                // Update the UI on the main thread with the error message and "No response"
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Error sending/receiving UDP packet: ${e.message}", Toast.LENGTH_SHORT).show()
                    textViewResponse.text = "No response"
                }
            }
        }
    }


}
