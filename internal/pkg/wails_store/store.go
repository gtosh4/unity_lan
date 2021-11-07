package wails_store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sync"

	"github.com/wailsapp/wails/runtime"
)

type Store struct {
	name                string
	dataType            reflect.Type
	callbacks           []reflect.Value
	runtime             *runtime.Runtime
	notifySynchronously bool

	mux  sync.Mutex
	data reflect.Value

	// Error handler
	errorHandler func(error)
}

// New creates a new store
func NewStore(rt *runtime.Runtime, name string, defaultValue interface{}) *Store {
	dataType := reflect.TypeOf(defaultValue)

	result := Store{
		name:     name,
		runtime:  rt,
		data:     reflect.ValueOf(defaultValue),
		dataType: dataType,
	}

	result.setupListener()

	return &result
}

// OnError takes a function that will be called
// whenever an error occurs
func (s *Store) OnError(callback func(error)) {
	s.errorHandler = callback
}

func (s *Store) UseAsyncCallbacks(enable bool) {
	s.mux.Lock()
	s.notifySynchronously = !enable
	s.mux.Unlock()
}

// Processes the updates sent by the front end
func (s *Store) processUpdatedData(data string) error {

	// Decode incoming data
	var rawdata json.RawMessage
	d := json.NewDecoder(bytes.NewBufferString(data))
	err := d.Decode(&rawdata)
	if err != nil {
		return err
	}

	// Create a new instance of our data and unmarshal
	// the received value into it
	newData := reflect.New(s.dataType).Interface()
	err = json.Unmarshal(rawdata, &newData)
	if err != nil {
		return err
	}

	s.updateFromRaw(newData)

	return nil
}

func (s *Store) updateFromRaw(data interface{}) {
	s.mux.Lock()
	if data == nil {
		s.data = reflect.Zero(s.dataType)
	} else {
		s.data = reflect.ValueOf(data).Elem()
	}
	s.mux.Unlock()
}

// Setup listener for front end changes
func (s *Store) setupListener() {

	// Listen for updates from the front end
	s.runtime.Events.On("wails:sync:store:updatedbyfrontend:"+s.name, func(data ...interface{}) {

		// Process the incoming data
		if len(data) == 0 {
			s.updateFromRaw(nil)
		} else {
			err := s.processUpdatedData(data[0].(string))
			if err != nil {
				if s.errorHandler != nil {
					s.errorHandler(err)
				}
				return
			}
		}

		s.notify()
	})

	s.runtime.Events.On("wails:sync:store:requestvalue:"+s.name, func(_ ...interface{}) {
		s.mux.Lock()
		v := s.data.Interface()
		s.mux.Unlock()
		payload, err := json.Marshal(v)
		if err != nil {
			if s.errorHandler != nil {
				s.errorHandler(err)
			}
			return
		}
		s.runtime.Events.Emit("wails:sync:store:updatedbybackend:"+s.name, string(payload))
	})
}

// notify the listeners of the current data state
func (s *Store) notify() {
	s.mux.Lock()
	cb := s.callbacks
	sync := s.notifySynchronously
	s.mux.Unlock()

	for _, callback := range cb {
		args := []reflect.Value{s.data}

		if sync {
			callback.Call(args)
		} else {
			go callback.Call(args)
		}
	}
}

// Set will update the data held by the store
// and notify listeners of the change
func (s *Store) Set(data interface{}) error {

	inType := reflect.TypeOf(data)

	if inType != s.dataType {
		return fmt.Errorf("invalid data given in Store.Set(). Expected %s, got %s", s.dataType.String(), inType.String())
	}

	// Save data
	s.mux.Lock()
	s.data = reflect.ValueOf(data)
	s.mux.Unlock()

	// Stringify data
	newdata, err := json.Marshal(data)
	if err != nil {
		if s.errorHandler != nil {
			return err
		}
	}

	// Emit event to front end
	s.runtime.Events.Emit("wails:sync:store:updatedbybackend:"+s.name, string(newdata))

	// Notify subscribers
	s.notify()

	return nil
}

// callbackCheck ensures the given function to Subscribe() is
// of the correct signature. Absolutely cannot wait for
// generics to land rather than writing this nonsense.
func (s *Store) callbackCheck(callback interface{}) error {

	// Get type
	callbackType := reflect.TypeOf(callback)

	// Check callback is a function
	if callbackType.Kind() != reflect.Func {
		return fmt.Errorf("invalid value given to store.Subscribe(). Expected 'func(%s)'", s.dataType.String())
	}

	// Check input param
	if callbackType.NumIn() != 1 {
		return fmt.Errorf("invalid number of parameters given in callback function. Expected 1")
	}

	// Check input data type
	if callbackType.In(0) != s.dataType {
		return fmt.Errorf("invalid type for input parameter given in callback function. Expected %s, got %s", s.dataType.String(), callbackType.In(0))
	}

	// Check output param
	if callbackType.NumOut() != 0 {
		return fmt.Errorf("invalid number of return parameters given in callback function. Expected 0")
	}

	return nil
}

// Subscribe will subscribe to updates to the store by
// providing a callback. Any updates to the store are sent
// to the callback
func (s *Store) Subscribe(callback interface{}) {

	err := s.callbackCheck(callback)
	if err != nil {
		log.Fatal(err)
	}

	callbackFunc := reflect.ValueOf(callback)

	s.callbacks = append(s.callbacks, callbackFunc)
}

// updaterCheck ensures the given function to Update() is
// of the correct signature. Absolutely cannot wait for
// generics to land rather than writing this nonsense.
func (s *Store) updaterCheck(updater interface{}) error {

	// Get type
	updaterType := reflect.TypeOf(updater)

	// Check updater is a function
	if updaterType.Kind() != reflect.Func {
		return fmt.Errorf("invalid value given to store.Update(). Expected 'func(%s) %s'", s.dataType.String(), s.dataType.String())
	}

	// Check input param
	if updaterType.NumIn() != 1 {
		return fmt.Errorf("invalid number of parameters given in updater function. Expected 1")
	}

	// Check input data type
	if updaterType.In(0) != s.dataType {
		return fmt.Errorf("invalid type for input parameter given in updater function. Expected %s, got %s", s.dataType.String(), updaterType.In(0))
	}

	// Check output param
	if updaterType.NumOut() != 1 {
		return fmt.Errorf("invalid number of return parameters given in updater function. Expected 1")
	}

	// Check output data type
	if updaterType.Out(0) != s.dataType {
		return fmt.Errorf("invalid type for return parameter given in updater function. Expected %s, got %s", s.dataType.String(), updaterType.Out(0))
	}

	return nil
}

// Update takes a function that is passed the current state.
// The result of that function is then set as the new state
// of the store. This will notify listeners of the change
func (s *Store) Update(updater interface{}) {

	err := s.updaterCheck(updater)
	if err != nil {
		log.Fatal(err)
	}

	// Build args
	args := []reflect.Value{s.data}

	// Make call
	results := reflect.ValueOf(updater).Call(args)

	// We will only have 1 result. Set the store to it
	err = s.Set(results[0].Interface())
	if err != nil && s.errorHandler != nil {
		s.errorHandler(err)
	}
}

// Get returns the value of the data that's kept in the current state / Store
func (s *Store) Get() interface{} {
	return s.data.Interface()
}
