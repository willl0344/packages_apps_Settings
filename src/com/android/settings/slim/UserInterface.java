/*
 * Copyright (C) 2012 Slimroms Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.settings.slim;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.net.wifi.WifiManager;
import android.preference.CheckBoxPreference;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.Preference.OnPreferenceChangeListener;
import android.preference.PreferenceCategory;
import android.preference.PreferenceScreen;
import android.provider.Settings;
import android.provider.Settings.SettingNotFoundException;
import android.util.Log;
import android.view.IWindowManager;
import android.widget.Toast;

import com.android.settings.R;
import com.android.settings.SettingsPreferenceFragment;
import com.android.settings.Utils;

public class UserInterface extends SettingsPreferenceFragment implements OnPreferenceChangeListener {

    public static final String TAG = "UserInterface";

    private static final String MISC_SETTINGS = "misc";
    private static final String PREF_USE_ALT_RESOLVER = "use_alt_resolver";
    private static final String KEY_COUNTRY_CODE = "wifi_countrycode";
    private static final String KEY_HARDWARE_KEYS = "hardware_keys";
    private static final String KEY_RECENTS_RAM_BAR = "recents_ram_bar";

    private Preference mLcdDensity;
    private CheckBoxPreference mUseAltResolver;
    private ListPreference mCcodePref;
    private PreferenceCategory mMisc;
    private CheckBoxPreference mRamBar;

    private WifiManager mWifiManager;

    int newDensityValue;

    DensityChanger densityFragment;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Load the preferences from an XML resource
        addPreferencesFromResource(R.xml.user_interface_settings);

        PreferenceScreen prefs = getPreferenceScreen();

        mMisc = (PreferenceCategory) prefs.findPreference(MISC_SETTINGS);

        mUseAltResolver = (CheckBoxPreference) findPreference(PREF_USE_ALT_RESOLVER);
        mUseAltResolver.setChecked(Settings.System.getInt(
                getActivity().getContentResolver(),
                Settings.System.ACTIVITY_RESOLVER_USE_ALT, 0) == 1);

        mLcdDensity = findPreference("lcd_density_setup");
        String currentProperty = SystemProperties.get("ro.sf.lcd_density");
        try {
            newDensityValue = Integer.parseInt(currentProperty);
        } catch (Exception e) {
            getPreferenceScreen().removePreference(mLcdDensity);
        }
        mLcdDensity.setSummary(getResources().getString(R.string.current_lcd_density) + currentProperty);

        mWifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);

        mCcodePref = (ListPreference) findPreference(KEY_COUNTRY_CODE);
        mCcodePref.setOnPreferenceChangeListener(this);

        updateWifiCodeSummary();

        // Only show the hardware keys config on a device that does not have a navbar
        IWindowManager windowManager = IWindowManager.Stub.asInterface(
                ServiceManager.getService(Context.WINDOW_SERVICE));
        try {
            if (windowManager.hasNavigationBar()) {
                mMisc.removePreference(findPreference(KEY_HARDWARE_KEYS));
            }
        } catch (RemoteException e) {
            // Do nothing
        }

        mRamBar = (CheckBoxPreference) findPreference(KEY_RECENTS_RAM_BAR);
        mRamBar.setChecked(Settings.System.getInt(
                getActivity().getContentResolver(),
                Settings.System.RECENTS_RAM_BAR, 0) == 1);

    }

    @Override
    public void onResume() {
        super.onResume();
        updateWifiCodeSummary();
    }

    @Override
    public void onPause() {
        super.onResume();
        updateWifiCodeSummary();
    }

    private void updateWifiCodeSummary() {
        if (mCcodePref != null) {
            String value = (mWifiManager.getCountryCode()).toUpperCase();
            if (value != null) {
                mCcodePref.setValue(value);
                mCcodePref.setSummary(mCcodePref.getEntry());
            } else {
                Log.e(TAG, "Failed to fetch country code");
            }
            if (mWifiManager.isWifiEnabled()) {
                mCcodePref.setEnabled(true);
            } else {
                mCcodePref.setEnabled(false);
                mCcodePref.setSummary(R.string.wifi_setting_countrycode_diabled);
            }
        }

    }

    public boolean onPreferenceChange(Preference preference, Object newValue) {
        boolean result = false;
        if (preference == mCcodePref) {
            try {
                Settings.Global.putString(mContext.getContentResolver(),
                       Settings.Global.WIFI_COUNTRY_CODE_USER,
                       (String) newValue);
                mWifiManager.setCountryCode((String) newValue, true);
                int index = mCcodePref.findIndexOfValue((String) newValue);
                mCcodePref.setSummary(mCcodePref.getEntries()[index]);
                return true;
            } catch (IllegalArgumentException e) {
                Toast.makeText(getActivity(), R.string.wifi_setting_countrycode_error,
                        Toast.LENGTH_SHORT).show();
                return false;
            }
        }
        return false;
    }

    @Override
    public boolean onPreferenceTreeClick(PreferenceScreen preferenceScreen,
            Preference preference) {
        if (preference == mUseAltResolver) {
            Settings.System.putInt(getActivity().getContentResolver(),
                    Settings.System.ACTIVITY_RESOLVER_USE_ALT,
                    ((CheckBoxPreference) preference).isChecked() ? 1 : 0);
            return true;
        } else if (preference == mRamBar) {
            Settings.System.putInt(getActivity().getContentResolver(),
                    Settings.System.RECENTS_RAM_BAR,
                    ((CheckBoxPreference) preference).isChecked() ? 1 : 0);
            return true;
        }
        return super.onPreferenceTreeClick(preferenceScreen, preference);
    }

}