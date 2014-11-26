if SwitchUser.generate_routes
  Rails.application.routes.draw do
    get :switch_user, :to => 'switch_user#set_current_user'
    get 'switch_user/remember_user', :to => 'switch_user#remember_user'
    get 'switch_user/switch_back', :to => 'switch_user#switch_back', :as => "switch_back"
  end
end
