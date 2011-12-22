package org.nick.ecdhkx;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity implements OnClickListener {

    private static String TAG = MainActivity.class.getSimpleName();

    private static String KPA_KEY = "kpA";
    private static String KPB_KEY = "kpB";

    private static final String CURVE_NAME = "secp160k1";

    private TextView curveNameText;
    private TextView fpSizeText;
    private TextView sharedKeyAText;
    private TextView sharedKeyBText;

    private Button listAlgsButton;
    private Button generateKeysButton;
    private Button ecdhButton;
    private Button clearButton;

    private Crypto crypto;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        setProgressBarIndeterminateVisibility(false);

        crypto = Crypto.getInstance();

        curveNameText = (TextView) findViewById(R.id.curve_name_text);
        fpSizeText = (TextView) findViewById(R.id.fp_size_text);
        sharedKeyAText = (TextView) findViewById(R.id.ska_text);
        sharedKeyBText = (TextView) findViewById(R.id.skb_text);

        listAlgsButton = (Button) findViewById(R.id.list_algs_button);
        listAlgsButton.setOnClickListener(this);

        generateKeysButton = (Button) findViewById(R.id.generate_keys_button);
        generateKeysButton.setOnClickListener(this);

        ecdhButton = (Button) findViewById(R.id.ecdh_button);
        ecdhButton.setOnClickListener(this);

        clearButton = (Button) findViewById(R.id.clear_button);
        clearButton.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        SharedPreferences prefs = PreferenceManager
                .getDefaultSharedPreferences(this);
        if (v.getId() == R.id.list_algs_button) {
            Crypto.listAlgorithms("EC");
            Crypto.listCurves();
        } else if (v.getId() == R.id.generate_keys_button) {
            generateKeys(prefs);
        } else if (v.getId() == R.id.ecdh_button) {
            ecdh(prefs);
        } else if (v.getId() == R.id.clear_button) {
            clear(prefs);
        }
    }

    private void generateKeys(SharedPreferences prefs) {
        final SharedPreferences.Editor prefsEditor = prefs.edit();

        new AsyncTask<Void, Void, Boolean>() {

            ECParams ecp;
            Exception error;

            @Override
            protected void onPreExecute() {
                Toast.makeText(MainActivity.this, "Generating ECDH keys...",
                        Toast.LENGTH_SHORT).show();

                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected Boolean doInBackground(Void... arg0) {
                try {
                    ecp = ECParams.getParams(CURVE_NAME);
                    KeyPair kpA = crypto.generateKeyPairParams(ecp);
                    // saveToFile("kpA_public.der",
                    // kpA.getPublic().getEncoded());
                    // saveToFile("kpA_private.der",
                    // kpA.getPrivate().getEncoded());
                    KeyPair kpB = crypto.generateKeyPairNamedCurve(CURVE_NAME);

                    saveKeyPair(prefsEditor, KPA_KEY, kpA);
                    saveKeyPair(prefsEditor, KPB_KEY, kpB);

                    return prefsEditor.commit();
                } catch (Exception e) {
                    Log.e(TAG, "Error doing ECDH: " + e.getMessage(), error);
                    error = e;

                    return false;
                }
            }

            @Override
            protected void onPostExecute(Boolean result) {
                setProgressBarIndeterminateVisibility(false);

                if (result) {
                    curveNameText.setText("Curve name: " + ecp.name);
                    fpSizeText.setText("Field size: "
                            + Integer.toString(ecp.getField().getFieldSize()));

                    Toast.makeText(MainActivity.this,
                            "Successfully generated and saved keys.",
                            Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(
                            MainActivity.this,
                            error == null ? "Error saving keys" : error
                                    .getMessage(), Toast.LENGTH_LONG).show();
                }
            }

        }.execute();
    }

    private void ecdh(final SharedPreferences prefs) {
        new AsyncTask<Void, Void, String[]>() {

            Exception error;

            @Override
            protected void onPreExecute() {
                Toast.makeText(MainActivity.this,
                        "Calculating shared ECDH key...", Toast.LENGTH_SHORT)
                        .show();

                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected String[] doInBackground(Void... arg0) {
                try {
                    KeyPair kpA = readKeyPair(prefs, KPA_KEY);
                    if (kpA == null) {
                        throw new IllegalArgumentException(
                                "Key A not found. Generate keys first.");
                    }
                    KeyPair kpB = readKeyPair(prefs, KPB_KEY);
                    if (kpB == null) {
                        throw new IllegalArgumentException(
                                "Key B not found. Generate keys first.");
                    }

                    byte[] aSecret = crypto.ecdh(kpA.getPrivate(),
                            kpB.getPublic());
                    byte[] bSecret = crypto.ecdh(kpB.getPrivate(),
                            kpA.getPublic());

                    return new String[] { Crypto.hex(aSecret),
                            Crypto.hex(bSecret) };
                } catch (Exception e) {
                    Log.e(TAG, "Error doing ECDH: " + e.getMessage(), error);
                    error = e;

                    return null;
                }
            }

            @Override
            protected void onPostExecute(String[] result) {
                setProgressBarIndeterminateVisibility(false);

                if (result != null && error == null) {
                    sharedKeyAText.setText(result[0]);
                    sharedKeyBText.setText(result[1]);
                } else {
                    Toast.makeText(MainActivity.this, error.getMessage(),
                            Toast.LENGTH_LONG).show();
                }
            }

        }.execute();
    }

    private void clear(SharedPreferences prefs) {
        curveNameText.setText("");
        fpSizeText.setText("");
        sharedKeyAText.setText("");
        sharedKeyBText.setText("");

        SharedPreferences.Editor prefsEditor = prefs.edit();
        prefsEditor.putString(KPA_KEY + "_private", null);
        prefsEditor.putString(KPA_KEY + "_public", null);
        prefsEditor.putString(KPB_KEY + "_private", null);
        prefsEditor.putString(KPB_KEY + "_public", null);

        prefsEditor.commit();

        Toast.makeText(MainActivity.this, "Deleted keys.", Toast.LENGTH_LONG)
                .show();
    }

    private void saveKeyPair(SharedPreferences.Editor prefsEditor, String key,
            KeyPair kp) {
        String pubStr = Crypto.base64Encode(kp.getPublic().getEncoded());
        String privStr = Crypto.base64Encode(kp.getPrivate().getEncoded());

        prefsEditor.putString(key + "_public", pubStr);
        prefsEditor.putString(key + "_private", privStr);
    }

    @SuppressWarnings("unused")
    private void saveToFile(String filename, byte[] bytes) throws Exception {
        File file = new File(Environment.getExternalStorageDirectory(),
                filename);
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(bytes);
        fos.flush();
        fos.close();
    }

    private KeyPair readKeyPair(SharedPreferences prefs, String key)
            throws Exception {
        String pubKeyStr = prefs.getString(key + "_public", null);
        String privKeyStr = prefs.getString(key + "_private", null);

        if (pubKeyStr == null || privKeyStr == null) {
            return null;
        }

        return crypto.readKeyPair(pubKeyStr, privKeyStr);
    }
}
