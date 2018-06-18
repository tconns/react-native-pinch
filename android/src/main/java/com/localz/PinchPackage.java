package com.localz;

import com.facebook.react.ReactPackage;
import com.facebook.react.bridge.JavaScriptModule;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;
import com.localz.RNPinch;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PinchPackage implements ReactPackage {
    private String SSL_KEY="";
    public PinchPackage(String ssl_key){
        SSL_KEY = ssl_key;
    }

    public List<Class<? extends JavaScriptModule>> createJSModules() {
        return Collections.emptyList();
    }

    @Override
    public List<ViewManager> createViewManagers(ReactApplicationContext reactContext) {
        return Collections.emptyList();
    }

    @Override
    public List<NativeModule> createNativeModules(
            ReactApplicationContext reactContext) {
        List<NativeModule> modules = new ArrayList<>();
        modules.add(new RNPinch(reactContext,SSL_KEY));
        return modules;
    }

}
