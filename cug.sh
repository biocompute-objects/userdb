#!/bin/bash

# Description:  The script for cloning the UserDB from GitHub.




# Deactivate the virtual environment.
deactivate

clear

# Make sure the script is being run as the correct user (beta_portal_user).
if [[ $(whoami) == 'beta_portal_user' ]]
then

	# See whether or not to preserve the existing database.
	if [[ $1 == '--drop-db' ]]
	then


		# Confirm the removal of the database.
		echo "##### WARNING!  YOU ARE ATTEMPTING TO REMOVE THE DATABASE ASSOCIATED WITH YOUR USERDB INSTALLATION!  CONFIRM THAT YOU WANT TO DO THIS BY TYPING \"REMOVE\" BELOW (NO QUOTES). #####"
		read remove_once

		# Do they actually want to remove the database?
		if [[ $remove_once == 'REMOVE' ]]
		then

			# Make sure no mistake was made.
			echo "----- CONFIRM REMOVAL OF THE USERDB DATABASE BY TYPING \"CONFIRM\" BELOW (NO QUOTES). -----"
			read remove_twice

			# Removal confirmation.
			if [[ $remove_twice == 'CONFIRM' ]]
			then


				# Make sure we're in the right directory.
				cd ~
				
				# Make the temporary directory.
				mkdir temp
				
				# Copy the settings file.
				cp ~/userdb/portalusers/settings.py ~/temp/settings.py

				# Remove the UserDB folder.
				rm userdb -rf

				# Clone the repository.
				git clone http://github.com/biocompute-objects/userdb
				
				# Replace the settings file.			
				cp ~/temp/settings.py ~/bco_api/bco_api/bco_api/settings.py

				# Get in the repository.
				cd userdb

				# Create the virtual environment and activate it.
				# ~/opt/bin/virtualenv env
				/home/beta_portal_user/.local/bin/virtualenv env
				source env/bin/activate

				# Install requirements.
				pip3.9 install -r requirements.txt

				# Migrate.
				python3.9 manage.py makemigrations
				python3.9 manage.py migrate
				
				# Remove the temp folder.
				rm ~/temp -rf
				
				# Deactivate the virtual environment.
				deactivate


			else


				# Invalid option provided.
				echo "Invalid value provided, leaving script..."
				exit 1
			
			
			fi


		else


			# Invalid option provided.
			echo "Invalid value provided, leaving script..."
			exit 1


		# Get out.
		fi


	elif [[ $1 == '--keep-db' ]]
	then


		# TODO: no need to copy settings.py either way
		# because everything for settings.py is set in server.conf.
		
		# No confirmation necessary for keeping the db.
		
		# Go through and keep everything.
		# Source: https://sqlite.org/cli.html (Step 9)

		# Make sure we're in the right directory.
		cd ~
		
		# Make the temporary directory.
		mkdir temp
		
		# *Dump* the existing database.
		sqlite3 ~/userdb/db.sqlite3 .dump | gzip -c > ~/temp/db.sqlite3.bak.gz
		
		# Only proceed if the backup was successful (i.e. the backup db exists).
		# Source: https://linuxize.com/post/bash-check-if-file-exists/
		if [ -e ~/temp/db.sqlite3.bak.gz ]
		then
		
			# The backup db exists, so proceed.
			
			# Copy the settings file.
			cp ~/userdb/portalusers/settings.py ~/temp/settings.py

			# Remove the UserDB folder.
			rm userdb -rf

			# Clone the repository.
			git clone http://github.com/biocompute-objects/userdb
			
			# Replace the settings file.			
			cp ~/temp/settings.py ~/bco_api/bco_api/bco_api/settings.py

			# Get in the repository.
			cd userdb

			# Create the virtual environment and activate it.
			# ~/opt/bin/virtualenv env
			/home/beta_portal_user/.local/bin/virtualenv env
			source env/bin/activate

			# Install requirements.
			pip3.9 install -r requirements.txt

			# Restore the backup.
			zcat ~/temp/db.sqlite3.bak.gz | sqlite3 ~/userdb/db.sqlite3
			
			# Remove the temp folder.
			rm ~/temp -rf
			
			# Deactivate the virtual environment.
			deactivate
		
		
		else
		
			# Couldn't make the sqlite backup.
			echo '~/temp/db.sqlite3.bak.gz was not found, leaving script...'
			exit 1
		
		fi	


	else


		# Bad parameters.
		echo 'Invalid parameters!  Please provide the --drop-db or --keep-db flag.'

		# Getoulathere.
		exit 1


	fi


	# Switch back to beta_portal_user's home directory
	# and change the ownership.
	cd ~
	chown beta_portal_user:nginx * -R

	# Restart the service.
	systemctl restart portal_users	

else

	# Wrong user.
	echo "SCRIPT FAILURE.  You must run this script as beta_portal_user."
	exit 1

fi
